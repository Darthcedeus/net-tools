"""Single-user web service for Subfinder, intended to sit behind Caddy HTTPS."""
import csv
import io
import json
import logging
import mimetypes
import os
import re
import secrets
import signal
import threading
import time
from collections import defaultdict, deque
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from app.runner import Runner
from app.security import normalize_domain, verify_password
from app.store import Store

STATIC = Path(__file__).parent / 'static'


class APIError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


class Application:
    def __init__(self):
        self.origin = os.environ.get('APP_ORIGIN', '').rstrip('/')
        parsed = urlsplit(self.origin)
        if parsed.scheme not in ('http', 'https') or not parsed.netloc or parsed.path or parsed.username or parsed.query or parsed.fragment:
            raise ValueError('APP_ORIGIN must be the exact public origin, e.g. https://subfinder.example.com')
        self.password_hash = os.environ.get('APP_PASSWORD_HASH', '')
        if not re.fullmatch(r'pbkdf2_sha256\$600000\$[0-9a-f]{32}\$[0-9a-f]{64}', self.password_hash):
            raise ValueError('Set APP_PASSWORD_HASH using scripts/setup.py before starting the application.')
        self.secure = parsed.scheme == 'https'
        self.sessions = {}
        self.attempts = defaultdict(deque)
        self.lock = threading.RLock()
        self.store = Store(Path(os.environ.get('DATA_DIR', '/data')) / 'scans.sqlite3')
        provider = os.environ.get('SUBFINDER_PROVIDER_CONFIG') or None
        if provider and not Path(provider).is_file():
            raise ValueError('SUBFINDER_PROVIDER_CONFIG must point to a readable file.')
        self.runner = Runner(self.store, os.environ.get('SUBFINDER_BIN', 'subfinder'), provider)

    def session(self, token):
        with self.lock:
            now = time.time()
            self.sessions = {k: v for k, v in self.sessions.items() if v['expires'] > now}
            return self.sessions.get(token)


class Handler(BaseHTTPRequestHandler):
    server_version = 'SubfinderGUI'
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

    def send(self, status, body, content_type='application/json; charset=utf-8', headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        if self.headers.get('Transfer-Encoding'):
            raise APIError(400, 'Chunked request bodies are not supported.')
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            raise APIError(415, 'Use a JSON request body.')
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 4096:
                raise APIError(413, 'Request body is too large or missing.')
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError()
            return data
        except (ValueError, UnicodeError):
            raise APIError(400, 'Invalid JSON request.') from None

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
            # Global + peer buckets prevent bypass through spoofed proxy headers.
            with self.app.lock:
                now = time.time()
                for key in ('global', self.client_address[0]):
                    bucket = self.app.attempts[key]
                    while bucket and bucket[0] < now - 300:
                        bucket.popleft()
                    if len(bucket) >= 10:
                        raise APIError(429, 'Too many sign-in attempts. Try again in five minutes.')
                for key in ('global', self.client_address[0]):
                    self.app.attempts[key].append(now)
            if not verify_password(password, self.app.password_hash):
                raise APIError(401, 'Incorrect password.')
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
            match = re.fullmatch(r'/api/scans/([a-f0-9]{32})(?:/(results|export|cancel))?', path)
            if match:
                scan_id, action = match.groups()
                scan = self.app.store.get(scan_id)
                if not scan:
                    raise APIError(404, 'Scan not found.')
                if method == 'GET' and not action:
                    return self.send(200, scan)
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
                        writer.writerow(['subdomain', 'sources'])
                        # Hostnames are validated; provider names are escaped for spreadsheet formulas.
                        for row in rows:
                            source = ', '.join(row['sources'])
                            if source.startswith(('=', '+', '-', '@', '\t', '\r')):
                                source = "'" + source
                            writer.writerow([row['host'], source])
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
                    self.app.store.delete(scan_id)
                    return self.send(200, {'ok': True})
            raise APIError(404, 'Endpoint not found.')
        if method == 'GET' and path in ('/', '/app.js', '/style.css', '/favicon.svg'):
            file = STATIC / ('index.html' if path == '/' else path[1:])
            return self.send(200, file.read_bytes(), mimetypes.guess_type(file.name)[0] or 'application/octet-stream')
        raise APIError(404, 'Not found.')

    def handle_request(self):
        try:
            self.dispatch()
        except APIError as error:
            self.close_connection = True
            self.send(error.status, {'error': error.message})
        except ValueError as error:
            self.close_connection = True
            self.send(400, {'error': str(error)})
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        except Exception:
            logging.exception('Request failed')
            self.close_connection = True
            self.send(500, {'error': 'An unexpected error occurred. Check server logs.'})

    do_GET = handle_request
    do_POST = handle_request
    do_DELETE = handle_request


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, address, app):
        self.app = app
        self.slots = threading.BoundedSemaphore(48)
        super().__init__(address, Handler)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(15)
        return request, address

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
    app = Application()
    server = Server((os.environ.get('HOST', '0.0.0.0'), int(os.environ.get('PORT', '8080'))), app)
    def stop(*_):
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    logging.info('Subfinder GUI listening on port %s', server.server_port)
    try:
        server.serve_forever(poll_interval=0.3)
    finally:
        app.runner.close()
        server.server_close()


if __name__ == '__main__':
    main()
