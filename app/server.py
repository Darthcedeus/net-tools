"""Single-user Net Tools web service, intended to sit behind Caddy HTTPS."""
import csv
import io
import ipaddress
import json
import logging
import mimetypes
import os
import re
import secrets
import signal
import socket
import threading
import time
from collections import defaultdict, deque
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from app.reach_runner import ReachabilityRunner
from app.runner import Runner
from app.salesforce import safe_target
from app.security import normalize_domain, proxy_token, verify_password
from app.sf_runner import SalesforceRunner
from app.store import Store, MAX_SF_BATCH_HOSTS, MAX_REACH_HOSTS

STATIC = Path(__file__).parent / 'static'


class APIError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


class Application:
    def __init__(self):
        self.origin = os.environ.get('APP_ORIGIN', '').rstrip('/')
        parsed = urlsplit(self.origin)
        if parsed.scheme not in ('http', 'https') or not parsed.netloc or parsed.path or parsed.username or parsed.query or parsed.fragment:
            raise ValueError('APP_ORIGIN must be the exact public origin, e.g. https://net-tools.humza.xyz')
        self.password_hash = os.environ.get('APP_PASSWORD_HASH', '')
        if not re.fullmatch(r'pbkdf2_sha256\$600000\$[0-9a-f]{32}\$[0-9a-f]{64}', self.password_hash):
            raise ValueError('Set APP_PASSWORD_HASH using scripts/setup.py before starting the application.')
        self.secure = parsed.scheme == 'https'
        self.proxy_token = proxy_token(self.password_hash)
        self.password_slots = threading.BoundedSemaphore(2)
        self.sessions = {}
        self.attempts = defaultdict(deque)
        self.lock = threading.RLock()
        self.store = Store(Path(os.environ.get('DATA_DIR', '/data')) / 'scans.sqlite3')
        provider = os.environ.get('SUBFINDER_PROVIDER_CONFIG') or None
        if provider and not Path(provider).is_file():
            raise ValueError('SUBFINDER_PROVIDER_CONFIG must point to a readable file.')
        self.runner = Runner(self.store, os.environ.get('SUBFINDER_BIN', 'subfinder'), provider)
        self.sf_runner = SalesforceRunner(self.store)
        self.reach_runner = ReachabilityRunner(self.store)

    def session(self, token):
        with self.lock:
            now = time.time()
            self.sessions = {k: v for k, v in self.sessions.items() if v['expires'] > now}
            return self.sessions.get(token)


class Handler(BaseHTTPRequestHandler):
    server_version = 'NetTools'
    protocol_version = 'HTTP/1.1'

    @property
    def app(self):
        return self.server.app

    def log_message(self, format, *args):
        # Never log passwords, cookies, or query-string searches.
        logging.info('%s %s', self.command, urlsplit(self.path).path)

    def token(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get('Cookie', ''))
            return cookie['sf_session'].value if 'sf_session' in cookie else ''
        except Exception:
            return ''

    def client_key(self):
        # Public backend ports make ordinary forwarding headers untrustworthy.
        tokens = self.headers.get_all('X-Net-Tools-Proxy-Token', [])
        addresses = self.headers.get_all('X-Net-Tools-Client-IP', [])
        if len(tokens) == len(addresses) == 1 and tokens[0].isascii() and secrets.compare_digest(tokens[0], self.app.proxy_token):
            try:
                return str(ipaddress.ip_address(addresses[0]))
            except ValueError:
                raise APIError(400, 'Invalid proxy client address.') from None
        return str(ipaddress.ip_address(self.client_address[0]))

    def send(self, status, body, content_type='application/json; charset=utf-8', headers=None):
        self.close_connection = True
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        try:
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            # The deadline can close the socket before even an error is sent.
            self.close_connection = True

    def body(self, max_bytes=4096):
        if self.headers.get('Transfer-Encoding'):
            raise APIError(400, 'Chunked request bodies are not supported.')
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            raise APIError(415, 'Use a JSON request body.')
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= max_bytes:
                raise APIError(413, 'Request body is too large or missing.')
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError()
            return data
        except (ValueError, UnicodeError):
            raise APIError(400, 'Invalid JSON request.') from None

    @staticmethod
    def sf_options(data):
        options = {}
        for key, default, low, high in [('sample_size', 10, 1, 25), ('max_objects', 50, 1, 200)]:
            value = data.get(key, default)
            if type(value) is not int or not low <= value <= high:
                raise APIError(400, f'{key} must be between {low} and {high}.')
            options[key] = value
        return options

    @staticmethod
    def reach_options(data):
        options = {}
        for key, default, low, high in [('timeout', 8, 3, 20), ('concurrency', 10, 1, 20)]:
            value = data.get(key, default)
            if type(value) is not int or not low <= value <= high:
                raise APIError(400, f'{key} must be between {low} and {high}.')
            options[key] = value
        return options

    def cookie(self, value, age):
        return f'sf_session={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={age}' + ('; Secure' if self.app.secure else '')

    def require_origin(self):
        if self.headers.get('Origin') != self.app.origin:
            raise APIError(403, 'Request origin does not match APP_ORIGIN.')

    def require_session(self, mutate=False):
        session = self.app.session(self.token())
        if not session:
            raise APIError(401, 'Sign in to continue.')
        if mutate:
            self.require_origin()
            if not secrets.compare_digest(self.headers.get('X-CSRF-Token', ''), session['csrf']):
                raise APIError(403, 'Refresh the page and try again.')
        return session

    def dispatch(self):
        parsed = urlsplit(self.path)
        path, query = parsed.path, parse_qs(parsed.query)
        method = self.command
        if path == '/healthz' and method == 'GET':
            return self.send(200, {'status': 'ok'})
        if path == '/api/session' and method == 'GET':
            session = self.app.session(self.token())
            return self.send(200, {'authenticated': bool(session), 'csrf': session['csrf'] if session else None,
                                   'engine_available': self.app.runner.available() if session else None})
        if path == '/api/login' and method == 'POST':
            self.require_origin()
            data = self.body()
            password = data.get('password', '')
            if not isinstance(password, str) or len(password) > 1024:
                raise APIError(400, 'Invalid password.')
            # Only this client gets a cooldown; password work is separately bounded.
            with self.app.lock:
                now = time.monotonic()
                for key in list(self.app.attempts):
                    bucket = self.app.attempts[key]
                    while bucket and bucket[0] <= now - 300:
                        bucket.popleft()
                    if not bucket:
                        del self.app.attempts[key]
                key = self.client_key()
                if key not in self.app.attempts and len(self.app.attempts) >= 4096:
                    raise APIError(503, 'Sign-in is busy. Try again shortly.')
                if len(self.app.attempts[key]) >= 10:
                    raise APIError(429, 'Too many sign-in attempts. Try again in five minutes.')
                if not self.app.password_slots.acquire(blocking=False):
                    raise APIError(503, 'Sign-in is busy. Try again shortly.')
                self.app.attempts[key].append(now)
            try:
                if not verify_password(password, self.app.password_hash):
                    raise APIError(401, 'Incorrect password.')
            finally:
                self.app.password_slots.release()
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            with self.app.lock:
                self.app.session('')
                if len(self.app.sessions) >= 128:
                    self.app.sessions.pop(next(iter(self.app.sessions)))
                self.app.sessions[token] = {'csrf': csrf, 'expires': time.time() + 43200}
            return self.send(200, {'csrf': csrf}, headers={'Set-Cookie': self.cookie(token, 43200)})
        if path.startswith('/api/'):
            self.require_session(mutate=method != 'GET')
            if path == '/api/logout' and method == 'POST':
                self.body()
                with self.app.lock:
                    self.app.sessions.pop(self.token(), None)
                return self.send(200, {'ok': True}, headers={'Set-Cookie': self.cookie('', 0)})
            if path == '/api/scans':
                if method == 'GET':
                    return self.send(200, self.app.store.history())
                if method == 'POST':
                    if not self.app.runner.available():
                        raise APIError(503, 'Subfinder is unavailable. Start the application with Docker to install the engine.')
                    data = self.body()
                    domain = normalize_domain(data.get('domain'))
                    opts = {}
                    for key, default, low, high in [('timeout', 30, 5, 60), ('max_time', 5, 1, 10), ('rate_limit', 10, 1, 50)]:
                        value = data.get(key, default)
                        if type(value) is not int or not low <= value <= high:
                            raise APIError(400, f'{key} must be between {low} and {high}.')
                        opts[key] = value
                    for key in ('all_sources', 'recursive'):
                        value = data.get(key, False)
                        if type(value) is not bool:
                            raise APIError(400, f'{key} must be true or false.')
                        opts[key] = value
                    return self.send(201, self.app.runner.submit(domain, opts))
            match = re.fullmatch(r'/api/scans/([a-f0-9]{32})(?:/(results|export|cancel|sf-batches|reach-batches))?', path)
            if match:
                scan_id, action = match.groups()
                scan = self.app.store.get(scan_id)
                if not scan:
                    raise APIError(404, 'Scan not found.')
                if method == 'GET' and not action:
                    return self.send(200, scan)
                if action == 'sf-batches':
                    if method == 'GET':
                        return self.send(200, self.app.store.sf_batches(scan_id))
                    if method == 'POST':
                        data = self.body(max_bytes=32768)
                        if scan['status'] in ('queued', 'running'):
                            raise APIError(409, 'Wait for subdomain discovery to finish before scanning its results.')
                        hosts = data.get('hosts')
                        if hosts is not None:
                            if not isinstance(hosts, list) or not 1 <= len(hosts) <= MAX_SF_BATCH_HOSTS:
                                raise APIError(400, f'Select between 1 and {MAX_SF_BATCH_HOSTS} hosts.')
                            hosts = sorted({normalize_domain(host) for host in hosts})
                        filter_query = data.get('q', '')
                        if not isinstance(filter_query, str) or len(filter_query) > 253 or (hosts is not None and filter_query):
                            raise APIError(400, 'Choose selected hosts or a subdomain filter, not both.')
                        return self.send(201, self.app.sf_runner.submit_batch(scan_id, self.sf_options(data), hosts, filter_query))
                if action == 'reach-batches':
                    if method == 'GET':
                        return self.send(200, self.app.store.reach_batches(scan_id))
                    if method == 'POST':
                        data = self.body(max_bytes=131072)
                        if scan['status'] in ('queued', 'running'):
                            raise APIError(409, 'Wait for subdomain discovery to finish before checking reachability.')
                        hosts = data.get('hosts')
                        if hosts is not None:
                            if not isinstance(hosts, list) or not 1 <= len(hosts) <= MAX_REACH_HOSTS:
                                raise APIError(400, f'Select between 1 and {MAX_REACH_HOSTS} hosts.')
                            hosts = sorted({normalize_domain(host) for host in hosts})
                        filter_query = data.get('q', '')
                        if not isinstance(filter_query, str) or len(filter_query) > 253 or (hosts is not None and filter_query):
                            raise APIError(400, 'Choose selected hosts or a subdomain filter, not both.')
                        try:
                            return self.send(201, self.app.reach_runner.submit_batch(scan_id, self.reach_options(data), hosts, filter_query))
                        except ValueError as error:
                            raise APIError(409, str(error)) from None
                if method == 'GET' and action == 'results':
                    try:
                        offset = int(query.get('offset', ['0'])[0])
                        if not 0 <= offset <= 10000:
                            raise ValueError()
                    except ValueError:
                        raise APIError(400, 'Invalid result offset.') from None
                    return self.send(200, self.app.store.results(scan_id, query.get('q', [''])[0][:253], offset))
                if method == 'GET' and action == 'export':
                    fmt = query.get('format', ['txt'])[0]
                    rows = self.app.store.results(scan_id, query.get('q', [''])[0][:253], limit=10000)['items']
                    if fmt == 'json':
                        body, mime = json.dumps({'scan': scan, 'results': rows}, indent=2), 'application/json'
                    elif fmt == 'csv':
                        output = io.StringIO()
                        writer = csv.writer(output)
                        writer.writerow(['subdomain', 'sources', 'ip_addresses', 'dns_status'])
                        # Hostnames are validated; provider names are escaped for spreadsheet formulas.
                        for row in rows:
                            source = ', '.join(row['sources'])
                            if source.startswith(('=', '+', '-', '@', '\t', '\r')):
                                source = "'" + source
                            writer.writerow([row['host'], source, ', '.join(row['ips']), row['dns_status']])
                        body, mime = output.getvalue(), 'text/csv; charset=utf-8'
                    elif fmt == 'txt':
                        body, mime = ''.join(r['host'] + '\n' for r in rows), 'text/plain; charset=utf-8'
                    else:
                        raise APIError(400, 'Choose txt, csv, or json.')
                    return self.send(200, body, mime, {'Content-Disposition': f'attachment; filename="{scan["domain"]}-{scan_id[:8]}.{fmt}"'})
                if method == 'POST' and action == 'cancel':
                    self.body()
                    self.app.runner.cancel(scan_id)
                    return self.send(200, {'ok': True})
                if method == 'DELETE' and not action:
                    if self.headers.get('Content-Length') or self.headers.get('Transfer-Encoding'):
                        self.body()
                    if scan['status'] in ('queued', 'running'):
                        raise APIError(409, 'Cancel the scan and wait for it to stop before deleting it.')
                    if any(batch['status'] in ('queued', 'running') for batch in self.app.store.sf_batches(scan_id)):
                        raise APIError(409, 'Cancel the Salesforce batch and wait for it to stop before deleting this discovery.')
                    self.app.store.delete(scan_id)
                    return self.send(200, {'ok': True})
            if path == '/api/activity' and method == 'GET':
                return self.send(200, self.app.store.activity())
            if path == '/api/activity/delete' and method == 'POST':
                data = self.body(max_bytes=65536)
                items = data.get('items')
                if (not isinstance(items, list) or not 1 <= len(items) <= 500 or any(
                        not isinstance(item, dict) or item.get('kind') not in ('subdomains', 'salesforce', 'salesforce_batch')
                        or not isinstance(item.get('id'), str) or not re.fullmatch(r'[a-f0-9]{32}', item['id']) for item in items)):
                    raise APIError(400, 'Select between 1 and 500 valid activities.')
                try:
                    result = self.app.store.delete_activities(items)
                except ValueError as error:
                    raise APIError(409, str(error)) from None
                return self.send(200, result)
            if path == '/api/sf-scans':
                if method == 'GET':
                    return self.send(200, self.app.store.sf_history())
                if method == 'POST':
                    data = self.body()
                    try:
                        url = safe_target(data.get('url'))
                    except ValueError as error:
                        raise APIError(400, str(error)) from None
                    return self.send(201, self.app.sf_runner.submit(url, self.sf_options(data)))
            match = re.fullmatch(r'/api/sf-batches/([a-f0-9]{32})(?:/(cancel|export))?', path)
            if match:
                batch_id, action = match.groups()
                batch = self.app.store.sf_batch_get(batch_id)
                if not batch:
                    raise APIError(404, 'Salesforce batch not found.')
                if method == 'GET' and not action:
                    return self.send(200, batch)
                if method == 'GET' and action == 'export':
                    return self.send(200, json.dumps(batch, indent=2), 'application/json',
                                     {'Content-Disposition': f'attachment; filename="{batch["source_domain"]}-salesforce-{batch_id[:8]}.json"'})
                if method == 'POST' and action == 'cancel':
                    self.body()
                    self.app.sf_runner.cancel_batch(batch_id)
                    return self.send(200, {'ok': True})
                if method == 'DELETE' and not action:
                    if batch['status'] in ('queued', 'running'):
                        raise APIError(409, 'Cancel the batch and wait for it to stop before deleting it.')
                    self.app.store.sf_batch_delete(batch_id)
                    return self.send(200, {'ok': True})
            match = re.fullmatch(r'/api/reach-batches/([a-f0-9]{32})(?:/(cancel|export))?', path)
            if match:
                batch_id, action = match.groups()
                batch = self.app.store.reach_batch_get(batch_id)
                if not batch:
                    raise APIError(404, 'Reachability batch not found.')
                if method == 'GET' and not action:
                    return self.send(200, batch)
                if method == 'GET' and action == 'export':
                    fmt = query.get('format', ['json'])[0]
                    if fmt == 'json':
                        body, mime = json.dumps(batch, indent=2), 'application/json'
                    elif fmt == 'csv':
                        output = io.StringIO()
                        writer = csv.writer(output)
                        writer.writerow(['host', 'reachable', 'scheme', 'status', 'server', 'final_url', 'error', 'elapsed_ms'])
                        for row in batch['items']:
                            server_name = row['server'] or ''
                            if server_name.startswith(('=', '+', '-', '@', '\t', '\r')):
                                server_name = "'" + server_name
                            writer.writerow([row['host'], '' if row['reachable'] is None else ('yes' if row['reachable'] else 'no'),
                                             row['scheme'] or '', '' if row['status'] is None else row['status'],
                                             server_name, row['final_url'] or '', row['error'] or '',
                                             '' if row['elapsed_ms'] is None else row['elapsed_ms']])
                        body, mime = output.getvalue(), 'text/csv; charset=utf-8'
                    else:
                        raise APIError(400, 'Choose json or csv.')
                    return self.send(200, body, mime, {'Content-Disposition': f'attachment; filename="{batch["source_domain"]}-reachability-{batch_id[:8]}.{fmt}"'})
                if method == 'POST' and action == 'cancel':
                    self.body()
                    self.app.reach_runner.cancel_batch(batch_id)
                    return self.send(200, {'ok': True})
                if method == 'DELETE' and not action:
                    if batch['status'] in ('queued', 'running'):
                        raise APIError(409, 'Cancel the batch and wait for it to stop before deleting it.')
                    self.app.store.reach_batch_delete(batch_id)
                    return self.send(200, {'ok': True})
            match = re.fullmatch(r'/api/sf-scans/([a-f0-9]{32})(?:/(findings|export|cancel))?', path)
            if match:
                scan_id, action = match.groups()
                scan = self.app.store.sf_get(scan_id)
                if not scan:
                    raise APIError(404, 'Scan not found.')
                if method == 'GET' and not action:
                    return self.send(200, scan)
                if method == 'GET' and action == 'findings':
                    try:
                        offset = int(query.get('offset', ['0'])[0])
                        if not 0 <= offset <= 10000:
                            raise ValueError()
                    except ValueError:
                        raise APIError(400, 'Invalid result offset.') from None
                    readable_only = query.get('readable', ['0'])[0] == '1'
                    return self.send(200, self.app.store.sf_findings(scan_id, query.get('q', [''])[0][:128], readable_only, offset))
                if method == 'GET' and action == 'export':
                    fmt = query.get('format', ['json'])[0]
                    rows = self.app.store.sf_findings(scan_id, query.get('q', [''])[0][:128], limit=10000)['items']
                    if fmt == 'json':
                        body, mime = json.dumps({'scan': scan, 'findings': rows}, indent=2), 'application/json'
                    elif fmt == 'csv':
                        output = io.StringIO()
                        writer = csv.writer(output)
                        writer.writerow(['object', 'key_prefix', 'readable', 'record_count', 'sample_count'])
                        for row in rows:
                            name = row['object']
                            if name.startswith(('=', '+', '-', '@', '\t', '\r')):
                                name = "'" + name
                            writer.writerow([name, row['key_prefix'] or '', 'yes' if row['readable'] else 'no',
                                             '' if row['record_count'] is None else row['record_count'], len(row['samples'])])
                        body, mime = output.getvalue(), 'text/csv; charset=utf-8'
                    else:
                        raise APIError(400, 'Choose json or csv.')
                    host = urlsplit(scan['url']).hostname or 'target'
                    return self.send(200, body, mime, {'Content-Disposition': f'attachment; filename="{host}-{scan_id[:8]}.{fmt}"'})
                if method == 'POST' and action == 'cancel':
                    self.body()
                    self.app.sf_runner.cancel(scan_id)
                    return self.send(200, {'ok': True})
                if method == 'DELETE' and not action:
                    if self.headers.get('Content-Length') or self.headers.get('Transfer-Encoding'):
                        self.body()
                    if scan['status'] in ('queued', 'running'):
                        raise APIError(409, 'Cancel the scan and wait for it to stop before deleting it.')
                    if scan['batch_id']:
                        raise APIError(409, 'Delete the Salesforce batch to remove this result.')
                    self.app.store.sf_delete(scan_id)
                    return self.send(200, {'ok': True})
            raise APIError(404, 'Endpoint not found.')
        # Explicit routes support direct visits and browser refreshes without
        # treating unknown tools, assets, or API paths as the application shell.
        pages = {'/', '/tools/subdomains', '/tools/salesforce', '/activity'}
        if method == 'GET' and path.rstrip('/') in {'/tools/subdomains', '/tools/salesforce', '/activity'}:
            path = path.rstrip('/')
        if method == 'GET' and path in pages | {'/app.js', '/tools.js', '/style.css', '/favicon.svg'}:
            file = STATIC / ('index.html' if path in pages else path[1:])
            return self.send(200, file.read_bytes(), mimetypes.guess_type(file.name)[0] or 'application/octet-stream')
        raise APIError(404, 'Not found.')

    def handle_request(self):
        client = None
        try:
            client = self.client_key()
            if not self.server.acquire_client(client):
                client = None
                raise APIError(429, 'Too many open requests from this client.')
            self.dispatch()
        except APIError as error:
            self.close_connection = True
            self.send(error.status, {'error': error.message})
        except ValueError as error:
            self.close_connection = True
            self.send(400, {'error': str(error)})
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True
        except Exception:
            logging.exception('Request failed')
            self.close_connection = True
            self.send(500, {'error': 'An unexpected error occurred. Check server logs.'})
        finally:
            if client is not None:
                self.server.release_client(client)

    do_GET = handle_request
    do_POST = handle_request
    do_DELETE = handle_request


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64
    connection_lifetime = 15
    peer_limit = 8
    client_limit = 4

    def __init__(self, address, app):
        self.app = app
        self.slots = threading.BoundedSemaphore(48)
        self.connection_lock = threading.Lock()
        self.connections = {}
        self.peers = defaultdict(int)
        self.clients = defaultdict(int)
        self.stopping = threading.Event()
        super().__init__(address, Handler)
        self.reaper = threading.Thread(target=self.expire_connections, daemon=True)
        self.reaper.start()

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(15)
        return request, address

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        peer = address[0]
        with self.connection_lock:
            if self.peers[peer] >= self.peer_limit:
                self.slots.release()
                self.shutdown_request(request)
                return
            self.peers[peer] += 1
            self.connections[request] = (time.monotonic() + self.connection_lifetime, peer)
        try:
            super().process_request(request, address)
        except Exception:
            self.finish_connection(request)
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.finish_connection(request)

    def finish_connection(self, request):
        with self.connection_lock:
            _, peer = self.connections.pop(request)
            self.peers[peer] -= 1
            if not self.peers[peer]:
                del self.peers[peer]
        self.slots.release()

    def acquire_client(self, client):
        with self.connection_lock:
            if self.clients[client] >= self.client_limit:
                return False
            self.clients[client] += 1
            return True

    def release_client(self, client):
        with self.connection_lock:
            self.clients[client] -= 1
            if not self.clients[client]:
                del self.clients[client]

    def expire_connections(self):
        # One watchdog bounds even buffered reads with continuously arriving bytes.
        while not self.stopping.wait(0.05):
            with self.connection_lock:
                for request, (deadline, _) in self.connections.items():
                    if time.monotonic() >= deadline:
                        try:
                            request.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass

    def server_close(self):
        self.stopping.set()
        self.reaper.join()
        with self.connection_lock:
            for request in self.connections:
                try:
                    request.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        super().server_close()


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
    app = Application()
    server = Server((os.environ.get('HOST', '0.0.0.0'), int(os.environ.get('PORT', '8080'))), app)
    def stop(*_):
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    logging.info('Net Tools listening on port %s', server.server_port)
    try:
        server.serve_forever(poll_interval=0.3)
    finally:
        app.runner.close()
        app.sf_runner.close()
        app.reach_runner.close()
        server.server_close()


if __name__ == '__main__':
    main()

