import http.client
import json
import os
import socket
import tempfile
import sqlite3
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from collections import deque

from app.runner import Runner
from app.resolver import resolve_host
import dns.exception
import dns.resolver
from app.security import hash_password, normalize_domain, proxy_token, verify_password
from app.server import Application, Server
from app.store import Store

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests' / 'fixtures' / 'subfinder.py'
FIXTURE.chmod(0o755)
PASSWORD = 'test-password-long-enough'
HASH = hash_password(PASSWORD)
OPTIONS = {'timeout': 5, 'max_time': 1, 'rate_limit': 10, 'all_sources': False, 'recursive': False}


def fixture_addresses(host):
    if host.startswith('docs.'):
        return [], 'no_records'
    if host.startswith('staging.'):
        return [], 'timeout'
    return ['192.0.2.10', '2001:db8::10'], 'resolved'


class ResolverTests(unittest.TestCase):
    def test_a_and_aaaa_deduplicate_sort_and_bound_requests(self):
        with patch('app.resolver.dns.resolver.Resolver') as factory:
            resolver = factory.return_value
            resolver.resolve.side_effect = [[SimpleNamespace(address=a) for a in ['192.0.2.20', '192.0.2.10', '192.0.2.10']], [SimpleNamespace(address='2001:db8::10')]]
            self.assertEqual(resolve_host('api.example.com'), (['192.0.2.10', '192.0.2.20', '2001:db8::10'], 'resolved'))
            self.assertEqual(resolver.timeout, 1)
            self.assertEqual(resolver.resolve.call_args_list[0].args, ('api.example.com.', 'A'))
            self.assertEqual(resolver.resolve.call_args_list[1].args, ('api.example.com.', 'AAAA'))
            for call in resolver.resolve.call_args_list:
                self.assertEqual(call.kwargs, {'lifetime': 1.5, 'search': False})

    def test_no_records_timeouts_and_failure_are_distinct(self):
        for error, status in [(dns.resolver.NoAnswer(), 'no_records'), (dns.resolver.NXDOMAIN(), 'no_records'), (dns.exception.Timeout(), 'timeout'), (dns.resolver.NoNameservers(), 'error')]:
            with self.subTest(status=status), patch('app.resolver.dns.resolver.Resolver') as factory:
                factory.return_value.resolve.side_effect = error
                self.assertEqual(resolve_host('api.example.com'), ([], status))

    def test_partial_family_failure_preserves_addresses(self):
        with patch('app.resolver.dns.resolver.Resolver') as factory:
            factory.return_value.resolve.side_effect = [[SimpleNamespace(address='192.0.2.10')], dns.exception.Timeout()]
            self.assertEqual(resolve_host('api.example.com'), (['192.0.2.10'], 'partial'))


def wait_for(store, scan_id, predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        scan = store.get(scan_id)
        if predicate(scan):
            return scan
        time.sleep(0.02)
    raise AssertionError(f'Scan did not reach expected state: {store.get(scan_id)}')


class SecurityTests(unittest.TestCase):
    def test_password_hash_and_wrong_password(self):
        self.assertTrue(verify_password(PASSWORD, HASH))
        self.assertFalse(verify_password('wrong', HASH))
        self.assertFalse(verify_password(PASSWORD, 'invalid'))
        self.assertNotEqual(hash_password(PASSWORD), HASH)

    def test_domain_normalization(self):
        self.assertEqual(normalize_domain(' EXAMPLE.com. '), 'example.com')
        self.assertEqual(normalize_domain('bücher.de'), 'xn--bcher-kva.de')
        for domain in ['https://example.com', 'example.com/path', '-d', 'example.com;id', '*.example.com', '127.0.0.1', 'localhost', 'a..com', 'a' * 64 + '.com', 'foo.com\n-o /tmp/x']:
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                normalize_domain(domain)


class StoreTests(unittest.TestCase):
    def test_migrates_original_database_and_retains_address_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'old.sqlite3'
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE results (scan_id TEXT NOT NULL, host TEXT NOT NULL, sources TEXT NOT NULL, PRIMARY KEY(scan_id,host))')
                db.execute('INSERT INTO results VALUES (?,?,?)', ('legacy', 'old.example.com', '["crtsh"]'))
            store = Store(path)
            self.assertEqual(store.results('legacy')['items'][0]['dns_status'], 'not_checked')
            self.assertEqual(store.results('legacy')['items'][0]['ips'], [])
            store.create('new', 'example.com', OPTIONS)
            store.add_result('new', 'api.example.com', ['crtsh'])
            store.set_addresses('new', 'api.example.com', ['192.0.2.10', '2001:db8::10'], 'resolved')
            store.add_result('new', 'api.example.com', ['other'])
            reopened = Store(path)
            self.assertEqual(reopened.results('new')['items'][0]['ips'], ['192.0.2.10', '2001:db8::10'])
            self.assertEqual(reopened.results('new')['items'][0]['sources'], ['crtsh', 'other'])

    def test_restart_retains_partial_results_and_marks_interrupted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'history.sqlite3'
            store = Store(path); store.create('id', 'example.com', OPTIONS)
            store.update('id', status='running')
            store.add_result('id', 'api.example.com', ['crtsh'])
            store.add_result('id', 'api.example.com', ['hackertarget'])
            reopened = Store(path)
            self.assertEqual(reopened.get('id')['status'], 'interrupted')
            self.assertEqual(reopened.get('id')['count'], 1)
            self.assertEqual(reopened.get('id')['tool'], 'subdomains')
            self.assertEqual(reopened.results('id')['items'][0]['sources'], ['crtsh', 'hackertarget'])
            self.assertEqual(reopened.results('id', '%')['total'], 0)
            reopened.delete('id')
            self.assertEqual(reopened.results('id')['total'], 0)

    def test_finished_history_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'history.sqlite3')
            for i in range(105):
                store.create(str(i), 'example.com', OPTIONS)
                store.update(str(i), status='completed')
            with store.connect() as db:
                count = db.execute('SELECT count(*) FROM scans').fetchone()[0]
            self.assertLessEqual(count, 101)
            self.assertEqual(len(store.history()), 100)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / 'history.sqlite3')
        self.runner = Runner(self.store, str(FIXTURE), resolver=fixture_addresses)

    def tearDown(self):
        self.runner.close(); self.directory.cleanup()

    def test_streaming_merge_normalization_and_scope(self):
        scan = self.runner.submit('example.com', OPTIONS)
        completed = wait_for(self.store, scan['id'], lambda s: s['status'] == 'completed')
        self.assertEqual(completed['count'], 5)
        row = self.store.results(scan['id'])['items'][0]
        self.assertEqual(row['host'], 'api.example.com')
        self.assertEqual(row['sources'], ['another', 'crtsh', 'hackertarget'])
        self.assertEqual(row['ips'], ['192.0.2.10', '2001:db8::10'])
        self.assertEqual(row['dns_status'], 'resolved')

    def test_resolves_only_unique_in_scope_hosts_and_isolates_dns_errors(self):
        calls = []
        def resolver(host):
            calls.append(host)
            if host.startswith('mail.'):
                raise RuntimeError('resolver error')
            return fixture_addresses(host)
        self.runner.resolver = resolver
        scan = self.runner.submit('example.com', OPTIONS)
        wait_for(self.store, scan['id'], lambda s: s['status'] == 'completed')
        self.assertEqual(len(calls), 5)
        self.assertEqual(len(set(calls)), 5)
        self.assertTrue(all(h.endswith('.example.com') for h in calls))
        rows = {r['host']: r for r in self.store.results(scan['id'])['items']}
        self.assertEqual(rows['docs.example.com']['dns_status'], 'no_records')
        self.assertEqual(rows['staging.example.com']['dns_status'], 'timeout')
        self.assertEqual(rows['mail.example.com']['dns_status'], 'error')
        self.assertFalse(any(r['dns_status'] == 'pending' for r in rows.values()))

    def test_dns_concurrency_and_cancel_discard_queued_lookups(self):
        fixture = Path(self.directory.name) / 'many.py'
        fixture.write_text('#!/usr/bin/env python3\nimport json\nfor i in range(32):\n print(json.dumps({"host":f"host{i}.example.com","source":"crtsh"}), flush=True)\n')
        fixture.chmod(0o755)
        self.runner.binary = str(fixture)
        release, eight_started = threading.Event(), threading.Event()
        calls, lock = [], threading.Lock()
        def blocked(host):
            with lock:
                calls.append(host)
                if len(calls) == 8:
                    eight_started.set()
            release.wait(2)
            return ['192.0.2.10'], 'resolved'
        self.runner.resolver = blocked
        scan = self.runner.submit('example.com', OPTIONS)
        try:
            self.assertTrue(eight_started.wait(2))
            wait_for(self.store, scan['id'], lambda s: s['count'] == 32)
            self.runner.cancel(scan['id'])
        finally:
            release.set()
        wait_for(self.store, scan['id'], lambda s: s['status'] == 'cancelled')
        self.assertEqual(len(calls), 8)
        rows = self.store.results(scan['id'])['items']
        self.assertEqual(sum(r['dns_status'] == 'cancelled' for r in rows), 24)
        self.assertFalse(any(r['dns_status'] == 'pending' for r in rows))

    def test_cancel_keeps_live_results_and_queued_cancel(self):
        scan = self.runner.submit('slow.example', OPTIONS)
        wait_for(self.store, scan['id'], lambda s: s['count'] == 1)
        queued = self.runner.submit('example.com', OPTIONS)
        self.runner.cancel(queued['id'])
        self.assertEqual(self.store.get(queued['id'])['status'], 'cancelled')
        self.runner.cancel(scan['id'])
        cancelled = wait_for(self.store, scan['id'], lambda s: s['status'] == 'cancelled')
        self.assertEqual(cancelled['count'], 1)

    def test_failure_does_not_expose_provider_secret(self):
        scan = self.runner.submit('failure.example', OPTIONS)
        failed = wait_for(self.store, scan['id'], lambda s: s['status'] == 'failed')
        self.assertNotIn('secret', failed['error'])

    def test_hard_deadline_and_result_cap(self):
        scan = self.runner.submit('slow.example', {**OPTIONS, 'max_time': -0.5})
        wait_for(self.store, scan['id'], lambda s: s['status'] == 'timed_out')
        self.runner.max_results = 2
        scan = self.runner.submit('example.com', OPTIONS)
        limited = wait_for(self.store, scan['id'], lambda s: s['status'] == 'limited')
        self.assertEqual(limited['count'], 2)

    def test_queue_limit(self):
        scan = self.runner.submit('slow.example', OPTIONS)
        wait_for(self.store, scan['id'], lambda s: s['status'] == 'running')
        for _ in range(5):
            self.runner.submit('example.com', OPTIONS)
        with self.assertRaises(ValueError):
            self.runner.submit('example.com', OPTIONS)


class APITests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.environment = patch.dict(os.environ, {'APP_ORIGIN': 'http://localhost:8080', 'APP_PASSWORD_HASH': HASH, 'DATA_DIR': self.directory.name, 'SUBFINDER_BIN': str(FIXTURE)})
        self.environment.start()
        self.dns_patch = patch('app.runner.resolve_host', side_effect=fixture_addresses)
        self.dns_patch.start()
        self.app = Application()
        self.server = Server(('127.0.0.1', 0), self.app)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start(); self.cookie = ''; self.csrf = ''

    def tearDown(self):
        self.server.shutdown(); self.app.runner.close(); self.server.server_close()
        self.environment.stop(); self.directory.cleanup()
        self.dns_patch.stop()

    def request(self, method, path, data=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        body = json.dumps(data) if data is not None else None
        default = {'Origin': self.app.origin, 'Content-Type': 'application/json', 'Cookie': self.cookie, 'X-CSRF-Token': self.csrf}
        connection.request(method, path, body=body, headers={**default, **(headers or {})})
        response = connection.getresponse(); raw = response.read().decode(); status = response.status
        response_headers = dict(response.getheaders())
        connection.close()
        return status, json.loads(raw) if 'application/json' in response_headers.get('Content-Type', '') else raw, response_headers

    def login(self):
        status, data, headers = self.request('POST', '/api/login', {'password': PASSWORD})
        self.assertEqual(status, 200)
        self.cookie = headers['Set-Cookie'].split(';')[0]; self.csrf = data['csrf']
        return headers

    def test_auth_csrf_origin_and_logout(self):
        self.assertEqual(self.request('GET', '/api/scans')[0], 401)
        self.assertEqual(self.request('POST', '/api/login', {'password': PASSWORD}, {'Origin': 'https://evil.example'})[0], 403)
        headers = self.login()
        self.assertIn('HttpOnly', headers['Set-Cookie']); self.assertIn('SameSite=Strict', headers['Set-Cookie'])
        self.assertEqual(self.request('POST', '/api/scans', {'domain': 'example.com'}, {'X-CSRF-Token': ''})[0], 403)
        self.assertEqual(self.request('POST', '/api/scans', {'domain': 'example.com'}, {'Origin': 'https://evil.example'})[0], 403)
        self.assertEqual(self.request('POST', '/api/logout', {})[0], 200)
        self.assertEqual(self.request('GET', '/api/scans')[0], 401)

    def test_scan_filter_exports_delete(self):
        self.login()
        status, scan, _ = self.request('POST', '/api/scans', {'domain': 'EXAMPLE.com.', **OPTIONS})
        self.assertEqual(status, 201)
        wait_for(self.app.store, scan['id'], lambda s: s['status'] == 'completed')
        prefix = '/api/scans/' + scan['id']
        results = self.request('GET', prefix + '/results?q=api')[1]
        self.assertEqual(results['total'], 1)
        self.assertEqual(results['items'][0]['ips'], ['192.0.2.10', '2001:db8::10'])
        self.assertEqual(self.request('GET', prefix + '/results?q=%25')[1]['total'], 0)
        self.assertEqual(len(self.request('GET', prefix + '/export?format=txt')[1].splitlines()), 5)
        self.assertEqual(self.request('GET', prefix + '/export?format=txt&q=api')[1], 'api.example.com\n')
        self.assertIn('subdomain,sources', self.request('GET', prefix + '/export?format=csv')[1])
        csv_export = self.request('GET', prefix + '/export?format=csv')[1]
        self.assertIn('ip_addresses,dns_status', csv_export)
        self.assertIn('2001:db8::10', csv_export)
        self.assertEqual(self.request('GET', prefix + '/export?format=json')[1]['results'][0]['ips'], ['192.0.2.10', '2001:db8::10'])
        self.assertEqual(len(self.request('GET', prefix + '/export?format=json')[1]['results']), 5)
        self.assertEqual(self.request('GET', prefix + '/export?format=html')[0], 400)
        self.assertEqual(self.request('DELETE', prefix)[0], 200)
        self.assertEqual(self.request('GET', prefix)[0], 404)

    def test_input_and_option_rejection(self):
        self.login()
        for body in [{'domain': 'example.com;id'}, {'domain': 'example.com', 'max_time': 99}, {'domain': 'example.com', 'timeout': True}, {'domain': 'example.com', 'all_sources': 'yes'}, {'domain': 'example.com', 'rate_limit': 0}]:
            with self.subTest(body=body):
                self.assertEqual(self.request('POST', '/api/scans', body)[0], 400)

    def test_login_rate_limit(self):
        attacker = {'X-Net-Tools-Proxy-Token': self.app.proxy_token, 'X-Net-Tools-Client-IP': '192.0.2.1'}
        for _ in range(10):
            self.assertEqual(self.request('POST', '/api/login', {'password': 'bad'}, attacker)[0], 401)
        self.assertEqual(self.request('POST', '/api/login', {'password': PASSWORD}, attacker)[0], 429)
        owner = {**attacker, 'X-Net-Tools-Client-IP': '192.0.2.2'}
        self.assertEqual(self.request('POST', '/api/login', {'password': PASSWORD}, owner)[0], 200)
        # A direct client with forged forwarding headers still uses its socket IP.
        for i in range(10):
            spoofed = {'X-Forwarded-For': f'198.51.100.{i}', 'X-Net-Tools-Client-IP': f'198.51.100.{i}', 'X-Net-Tools-Proxy-Token': 'forged'}
            self.assertEqual(self.request('POST', '/api/login', {'password': 'bad'}, spoofed)[0], 401)
        self.assertEqual(self.request('POST', '/api/login', {'password': PASSWORD})[0], 429)
        self.assertEqual(self.request('POST', '/api/login', {'password': PASSWORD}, owner)[0], 200)

    def test_proxy_validation_and_password_work_capacity(self):
        signed = {'X-Net-Tools-Proxy-Token': self.app.proxy_token, 'X-Net-Tools-Client-IP': 'not-an-ip'}
        self.assertEqual(self.request('POST', '/api/login', {'password': PASSWORD}, signed)[0], 400)
        for _ in range(2):
            self.app.password_slots.acquire()
        try:
            self.assertEqual(self.request('POST', '/api/login', {'password': PASSWORD})[0], 503)
            self.assertEqual(self.request('GET', '/healthz')[0], 200)
        finally:
            for _ in range(2):
                self.app.password_slots.release()
        self.login()

    def test_duplicate_proxy_headers_cannot_change_identity(self):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        connection.putrequest('GET', '/healthz')
        connection.putheader('X-Net-Tools-Proxy-Token', self.app.proxy_token)
        connection.putheader('X-Net-Tools-Proxy-Token', self.app.proxy_token)
        connection.putheader('X-Net-Tools-Client-IP', '192.0.2.1')
        # If the duplicate token were accepted this limit would return 429.
        with self.server.connection_lock:
            self.server.clients['192.0.2.1'] = self.server.client_limit
        try:
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
        finally:
            connection.close()
            with self.server.connection_lock:
                self.server.clients.pop('192.0.2.1', None)

    def test_login_buckets_expire_and_ipv6_aliases_share_quota(self):
        now = time.monotonic()
        with self.app.lock:
            self.app.attempts['2001:db8::1'] = deque([now] * 10)
        signed = {'X-Net-Tools-Proxy-Token': self.app.proxy_token, 'X-Net-Tools-Client-IP': '2001:0db8:0:0:0:0:0:1'}
        self.assertEqual(self.request('POST', '/api/login', {'password': PASSWORD}, signed)[0], 429)
        with self.app.lock:
            self.app.attempts['2001:db8::1'] = deque([now - 301] * 10)
        self.assertEqual(self.request('POST', '/api/login', {'password': PASSWORD}, signed)[0], 200)

    def test_login_tracking_is_bounded_and_recovers_after_expiry(self):
        now = time.monotonic()
        with self.app.lock:
            self.app.attempts.update({f'client-{i}': deque([now]) for i in range(4096)})
        self.assertEqual(self.request('POST', '/api/login', {'password': PASSWORD})[0], 503)
        with self.app.lock:
            self.assertEqual(len(self.app.attempts), 4096)
            for bucket in self.app.attempts.values():
                bucket[0] = now - 301
        self.login()

    def test_caddy_configuration_uses_matching_private_token(self):
        from scripts.caddy_config import render
        block = render(f"APP_ORIGIN='https://net-tools.humza.xyz'\nAPP_PASSWORD_HASH='{HASH}'\n")
        self.assertIn('header_up X-Net-Tools-Proxy-Token ' + proxy_token(HASH), block)
        self.assertIn('header_up X-Net-Tools-Client-IP {remote_host}', block)
        self.assertNotIn(HASH, block)
        self.assertNotEqual(proxy_token(HASH), proxy_token(hash_password(PASSWORD)))

    def test_successful_request_closes_persistent_socket(self):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        connection.request('GET', '/healthz')
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader('Connection'), 'close')
        response.read()
        self.assertIsNone(connection.sock)
        connection.close()
        with socket.create_connection(self.server.server_address, timeout=2) as wire:
            wire.sendall(b'GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n')
            response = b''
            while chunk := wire.recv(4096):
                response += chunk
            self.assertIn(b'200 OK', response)
            self.assertIn(b'Connection: close', response)

    def test_absolute_deadline_bounds_trickling_headers_and_bodies(self):
        self.server.connection_lifetime = 0.35
        for prefix in [b'GET /healthz HTTP/1.1\r\nX-Slow: ',
                       (f'POST /api/login HTTP/1.1\r\nOrigin: {self.app.origin}\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n').encode()]:
            with self.subTest(prefix=prefix), socket.create_connection(self.server.server_address, timeout=2) as connection:
                connection.sendall(prefix)
                started = time.monotonic()
                for _ in range(15):
                    time.sleep(0.04)
                    try:
                        connection.sendall(b' ')
                    except OSError:
                        break
                received = b''
                try:
                    while chunk := connection.recv(4096):
                        received += chunk
                except ConnectionResetError:
                    pass
                self.assertLess(time.monotonic() - started, 1.2)
        self.assertEqual(self.request('GET', '/healthz')[0], 200)

    def test_slow_client_cannot_fill_all_workers(self):
        self.server.connection_lifetime = 1
        connections = []
        try:
            for _ in range(self.server.peer_limit + 3):
                connection = socket.create_connection(self.server.server_address, timeout=2)
                connections.append(connection)
                try:
                    connection.sendall(b'GET /healthz HTTP/1.1\r\nX-Slow: ')
                except OSError:
                    pass
            time.sleep(0.1)
            with self.server.connection_lock:
                self.assertLessEqual(len(self.server.connections), self.server.peer_limit)
            # Hard deadline frees the admitted connections, even without EOF.
            time.sleep(1.1)
            self.assertEqual(self.request('GET', '/healthz')[0], 200)
        finally:
            for connection in connections:
                connection.close()

    def test_proxied_slow_bodies_leave_capacity_for_another_client(self):
        connections = []
        try:
            for _ in range(self.server.client_limit):
                connection = socket.create_connection(self.server.server_address, timeout=2)
                connections.append(connection)
                connection.sendall((f'POST /api/login HTTP/1.1\r\nOrigin: {self.app.origin}\r\nContent-Type: application/json\r\nContent-Length: 4096\r\nX-Net-Tools-Proxy-Token: {self.app.proxy_token}\r\nX-Net-Tools-Client-IP: 192.0.2.1\r\n\r\n').encode())
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                with self.server.connection_lock:
                    if self.server.clients.get('192.0.2.1') == self.server.client_limit:
                        break
                time.sleep(0.01)
            signed = {'X-Net-Tools-Proxy-Token': self.app.proxy_token, 'X-Net-Tools-Client-IP': '192.0.2.1'}
            self.assertEqual(self.request('GET', '/healthz', headers=signed)[0], 429)
            self.assertEqual(self.request('POST', '/api/login', {'password': PASSWORD}, {**signed, 'X-Net-Tools-Client-IP': '192.0.2.2'})[0], 200)
        finally:
            for connection in connections:
                connection.close()

    def test_keep_alive_consumes_cancel_and_logout_bodies(self):
        self.login()
        scan = self.request('POST', '/api/scans', {'domain': 'slow.example', **OPTIONS})[1]
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        headers = {'Origin': self.app.origin, 'Content-Type': 'application/json', 'Cookie': self.cookie, 'X-CSRF-Token': self.csrf}
        for method, path, body in [('POST', '/api/scans/' + scan['id'] + '/cancel', '{}'), ('GET', '/api/scans', None), ('POST', '/api/logout', '{}'), ('GET', '/api/session', None)]:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
        connection.close()

    def test_results_paginate_and_export_all_pages(self):
        self.login()
        scan_id = 'a' * 32
        self.app.store.create(scan_id, 'example.com', OPTIONS)
        for i in range(205):
            self.app.store.add_result(scan_id, f'host{i:03}.example.com', ['crtsh'])
        self.app.store.update(scan_id, status='completed')
        prefix = '/api/scans/' + scan_id
        first = self.request('GET', prefix + '/results')[1]
        second = self.request('GET', prefix + '/results?offset=200')[1]
        self.assertEqual(first['total'], 205); self.assertEqual(len(first['items']), 200)
        self.assertEqual(len(second['items']), 5)
        self.assertEqual(len(self.request('GET', prefix + '/export?format=txt')[1].splitlines()), 205)

    def test_static_security_headers_health_and_missing_engine(self):
        status, body, headers = self.request('GET', '/')
        self.assertEqual(status, 200); self.assertIn('Net Tools', body)
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        self.assertEqual(self.request('GET', '/healthz')[0], 200)
        self.login(); self.app.runner.binary = '/nonexistent/subfinder'
        self.assertEqual(self.request('POST', '/api/scans', {'domain': 'example.com'})[0], 503)

    def test_suite_routes_refresh_and_unknown_routes(self):
        for path in ['/', '/tools/subdomains', '/tools/subdomains/', '/activity', '/activity/', '/tools/subdomains?scan=' + 'a' * 32]:
            with self.subTest(path=path):
                status, body, headers = self.request('GET', path)
                self.assertEqual(status, 200)
                self.assertIn('Net Tools', body)
                self.assertIn('type="module"', body)
                self.assertTrue(headers['Content-Type'].startswith('text/html'))
        for path in ['/tools/dns', '/tools/not-implemented', '/missing.js', '/api/not-implemented', '/app/../security.py']:
            with self.subTest(path=path):
                self.assertIn(self.request('GET', path)[0], (401, 404))
        status, body, headers = self.request('GET', '/tools.js')
        self.assertEqual(status, 200)
        self.assertIn('available: false', body)
        self.assertIn('javascript', headers['Content-Type'])

    def test_suite_deep_links_do_not_bypass_api_auth(self):
        self.assertEqual(self.request('GET', '/tools/subdomains')[0], 200)
        self.assertEqual(self.request('GET', '/api/scans')[0], 401)
        self.login()
        scan = self.request('POST', '/api/scans', {'domain': 'example.com', **OPTIONS})[1]
        self.assertEqual(scan['tool'], 'subdomains')
        wait_for(self.app.store, scan['id'], lambda s: s['status'] == 'completed')
        self.assertEqual(self.request('GET', '/api/scans')[1][0]['tool'], 'subdomains')


from urllib.parse import parse_qs
from app import salesforce
from app.salesforce import Detector, FetchResult, safe_target
from app.sf_runner import SalesforceRunner


def aura(actions, context_fwuid=None):
    """Build a fake Aura response for the given list of (descriptor-hint, payload)."""
    body = {'actions': [{'id': str(i), 'descriptor': descriptor, **payload}
                        for i, (descriptor, payload) in enumerate(actions)]}
    return FetchResult(200, {}, json.dumps(body).encode(), 'https://x/aura')


def sf_fetch(landing='', object_data=None, locked=False, require_fwuid=None, aura_live=True):
    """A fake fetch for the Detector.

    object_data maps object name -> (totalCount, [records]). Objects absent from
    the map respond with an ERROR action (no guest access). When aura_live is
    False, the Aura endpoint responds like a non-Salesforce site (404 HTML).
    """
    object_data = object_data or {}

    def fetch(method, url, headers=None, data=None, timeout=10, max_bytes=0):
        if method == 'GET':
            return FetchResult(200, {}, landing.encode(), url)
        if not aura_live:
            return FetchResult(404, {}, b'<html>Not found</html>', url)
        params = parse_qs(data.decode())
        context = json.loads(params['aura.context'][0])
        message = json.loads(params['message'][0])
        descriptor = message['actions'][0]['descriptor']
        params0 = message['actions'][0].get('params', {})
        if require_fwuid and context.get('fwuid') != require_fwuid:
            body = json.dumps({'actions': [], 'event': 'aura:clientOutOfSync',
                               'newFwuid': require_fwuid}).encode()
            return FetchResult(200, {}, body, url)
        if 'getConfigData' in descriptor:
            return aura([(descriptor, {'state': 'SUCCESS', 'returnValue': {
                'apiNamesToKeyPrefixes': {'Account': '001', 'Secret__c': 'a01'}}})])
        if 'getItems' in descriptor:
            name = params0.get('entityNameOrId')
            if locked or name not in object_data:
                return aura([(descriptor, {'state': 'ERROR', 'error': [{'message': 'denied'}]})])
            total, records = object_data[name]
            return aura([(descriptor, {'state': 'SUCCESS', 'returnValue': {
                'totalCount': total, 'result': records}})])
        return FetchResult(500, {}, b'{}', url)
    return fetch


LANDING = ('<html><script>window.Aura={};var x="/auraFW/javascript/FWUID123/";'
           '"fwuid":"FWUID123","app":"siteforce:communityApp",'
           '"APPLICATION@markup://siteforce:communityApp":"APPID1"</script>'
           'siteforce:communityApp SelfRegister "apiName":"Custom__c"</html>')


class SalesforceSafeTargetTests(unittest.TestCase):
    def test_rejects_private_loopback_ip_scheme_and_credentials(self):
        for bad in ['http://localhost/', 'https://127.0.0.1', 'https://10.0.0.1',
                    'http://169.254.169.254/', 'ftp://example.com',
                    'https://user:pass@example.com', '', '   ']:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                safe_target(bad)

    def test_normalizes_public_host(self):
        with patch('app.salesforce._addresses_are_public'):
            self.assertEqual(safe_target('community.example.com/path?q=1'), 'https://community.example.com')
            self.assertEqual(safe_target('http://example.org:8080'), 'http://example.org:8080')


class SalesforceDetectorTests(unittest.TestCase):
    def setUp(self):
        self.public = patch('app.salesforce._addresses_are_public'); self.public.start()

    def tearDown(self):
        self.public.stop()

    def run_detector(self, fetch, **kwargs):
        findings, meta = [], {}
        detector = Detector(fetch=fetch, **kwargs)

        def emit(kind, payload):
            (findings.append(payload) if kind == 'finding' else meta.update(payload))
        summary = detector.run('https://community.example.com', lambda: False, emit)
        return summary, findings

    def test_not_salesforce(self):
        summary, findings = self.run_detector(sf_fetch(landing='<html>plain site</html>', aura_live=False))
        self.assertFalse(summary['is_salesforce'])
        self.assertEqual(summary['verdict'], 'not_salesforce')
        self.assertEqual(findings, [])

    def test_salesforce_locked_down(self):
        summary, findings = self.run_detector(sf_fetch(landing=LANDING, locked=True))
        self.assertTrue(summary['is_salesforce'])
        self.assertEqual(summary['verdict'], 'salesforce')
        self.assertEqual(summary['objects_readable'], 0)
        self.assertTrue(all(not f['readable'] for f in findings))

    def test_leaking_records_and_samples(self):
        records = [{'Id': '001x%02d' % i, 'Name': 'Acme %d' % i} for i in range(20)]
        fetch = sf_fetch(landing=LANDING, object_data={'Account': (42, records)})
        summary, findings = self.run_detector(fetch, sample_size=10)
        self.assertEqual(summary['verdict'], 'leaking')
        self.assertGreaterEqual(summary['objects_readable'], 1)
        account = next(f for f in findings if f['object'] == 'Account')
        self.assertTrue(account['readable'])
        self.assertEqual(account['record_count'], 42)
        self.assertEqual(len(account['samples']), 10)
        self.assertEqual(account['samples'][0]['Name'], 'Acme 0')

    def test_sample_fields_and_values_are_truncated(self):
        record = {'Big': 'x' * 500, 'Nested': {'value': 'y' * 500},
                  **{'f%d' % i: i for i in range(40)}}
        fetch = sf_fetch(landing=LANDING, object_data={'Account': (1, [record])})
        _, findings = self.run_detector(fetch)
        sample = next(f for f in findings if f['object'] == 'Account')['samples'][0]
        self.assertLessEqual(len(sample), salesforce.SAMPLE_FIELD_LIMIT)
        self.assertLessEqual(len(sample['Big']), salesforce.SAMPLE_VALUE_LIMIT)
        # A nested field value is flattened to a truncated string, not kept as an object.
        self.assertIsInstance(sample['Nested'], str)
        self.assertLessEqual(len(sample['Nested']), salesforce.SAMPLE_VALUE_LIMIT)

    def test_fwuid_refresh_recovers_object_list(self):
        fetch = sf_fetch(landing='<html>window.Aura siteforce:communityApp</html>',
                         object_data={'Account': (3, [{'Id': '001', 'Name': 'A'}])},
                         require_fwuid='NEWFW')
        summary, findings = self.run_detector(fetch)
        self.assertTrue(summary['is_salesforce'])
        self.assertEqual(summary['fwuid'], 'NEWFW')
        self.assertEqual(summary['verdict'], 'leaking')

    def test_cancel_stops_before_probing(self):
        detector = Detector(fetch=sf_fetch(landing=LANDING, object_data={'Account': (1, [{'Id': '1'}])}))
        findings = []
        detector.run('https://community.example.com', lambda: True,
                     lambda kind, payload: findings.append(payload) if kind == 'finding' else None)
        self.assertEqual(findings, [])


class SalesforceStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / 'scans.sqlite3')

    def tearDown(self):
        self.directory.cleanup()

    def test_create_findings_and_activity_merge(self):
        self.store.sf_create('a' * 32, 'https://community.example.com', {'sample_size': 10, 'max_objects': 50})
        scan = self.store.sf_get('a' * 32)
        self.assertEqual(scan['tool'], 'salesforce')
        self.assertEqual(scan['status'], 'queued')
        self.store.sf_set_summary('a' * 32, {'verdict': 'leaking', 'is_salesforce': True,
                                             'aura_endpoint': 'https://community.example.com/aura'})
        self.store.sf_add_finding('a' * 32, {'object': 'Account', 'key_prefix': '001',
                                            'readable': True, 'record_count': 5, 'samples': [{'Id': '1'}]})
        self.store.sf_add_finding('a' * 32, {'object': 'Lead', 'readable': False, 'record_count': None, 'samples': []})
        scan = self.store.sf_get('a' * 32)
        self.assertEqual(scan['count'], 1)
        self.assertTrue(scan['is_salesforce'])
        readable = self.store.sf_findings('a' * 32, readable_only=True)
        self.assertEqual(readable['total'], 1)
        self.assertEqual(readable['items'][0]['object'], 'Account')
        self.assertEqual(self.store.sf_findings('a' * 32, query='lea')['total'], 1)
        # Combined activity includes both tools, newest first.
        self.store.create('b' * 32, 'example.com', {'timeout': 5})
        activity = self.store.activity()
        self.assertEqual({item['tool'] for item in activity}, {'salesforce', 'subdomains'})
        sf_item = next(item for item in activity if item['tool'] == 'salesforce')
        self.assertEqual(sf_item['verdict'], 'leaking')
        self.assertEqual(sf_item['label'], 'https://community.example.com')

    def test_not_salesforce_activity_verdict(self):
        self.store.sf_create('c' * 32, 'https://plain.example.com', {})
        self.store.sf_set_summary('c' * 32, {'verdict': 'not_salesforce', 'is_salesforce': False})
        item = next(i for i in self.store.activity() if i['tool'] == 'salesforce')
        self.assertEqual(item['verdict'], 'not_salesforce')


class SalesforceAPITests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.environment = patch.dict(os.environ, {'APP_ORIGIN': 'http://localhost:8080', 'APP_PASSWORD_HASH': HASH, 'DATA_DIR': self.directory.name, 'SUBFINDER_BIN': str(FIXTURE)})
        self.environment.start()
        self.public = patch('app.salesforce._addresses_are_public'); self.public.start()
        self.app = Application()
        records = [{'Id': '001x%02d' % i, 'Name': 'Acme %d' % i} for i in range(12)]
        self.app.sf_runner.detector = Detector(fetch=sf_fetch(landing=LANDING, object_data={'Account': (42, records)}))
        self.server = Server(('127.0.0.1', 0), self.app)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start(); self.cookie = ''; self.csrf = ''

    def tearDown(self):
        self.server.shutdown(); self.app.runner.close(); self.app.sf_runner.close(); self.server.server_close()
        self.public.stop(); self.environment.stop(); self.directory.cleanup()

    def request(self, method, path, data=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        body = json.dumps(data) if data is not None else None
        default = {'Origin': self.app.origin, 'Content-Type': 'application/json', 'Cookie': self.cookie, 'X-CSRF-Token': self.csrf}
        connection.request(method, path, body=body, headers={**default, **(headers or {})})
        response = connection.getresponse(); raw = response.read().decode(); status = response.status
        response_headers = dict(response.getheaders())
        connection.close()
        return status, json.loads(raw) if 'application/json' in response_headers.get('Content-Type', '') else raw, response_headers

    def login(self):
        status, data, headers = self.request('POST', '/api/login', {'password': PASSWORD})
        self.cookie = headers['Set-Cookie'].split(';')[0]; self.csrf = data['csrf']

    def wait_sf(self, scan_id, predicate, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            scan = self.app.store.sf_get(scan_id)
            if predicate(scan):
                return scan
            time.sleep(0.02)
        raise AssertionError(f'SF scan did not reach expected state: {self.app.store.sf_get(scan_id)}')

    def test_auth_csrf_and_url_validation(self):
        # Every Salesforce data endpoint sits behind the login gate; none can be
        # reached without a session, including reads of findings and exports.
        fake = 'f' * 32
        for method, path in [('GET', '/api/sf-scans'), ('GET', '/api/activity'),
                             ('POST', '/api/sf-scans'), ('GET', f'/api/sf-scans/{fake}'),
                             ('GET', f'/api/sf-scans/{fake}/findings'),
                             ('GET', f'/api/sf-scans/{fake}/export?format=csv'),
                             ('POST', f'/api/sf-scans/{fake}/cancel'),
                             ('DELETE', f'/api/sf-scans/{fake}')]:
            with self.subTest(path=path):
                self.assertEqual(self.request(method, path)[0], 401)
        self.login()
        # CSRF and origin are enforced on mutation.
        self.assertEqual(self.request('POST', '/api/sf-scans', {'url': 'community.example.com'}, {'X-CSRF-Token': ''})[0], 403)
        # SSRF / input validation rejects non-public or malformed targets.
        with patch('app.salesforce._addresses_are_public', side_effect=ValueError('private')):
            self.assertEqual(self.request('POST', '/api/sf-scans', {'url': 'http://169.254.169.254/'})[0], 400)
        for body in [{'url': 'ftp://example.com'}, {'url': 'community.example.com', 'sample_size': 99},
                     {'url': 'community.example.com', 'max_objects': 0}, {'url': 123}]:
            with self.subTest(body=body):
                self.assertEqual(self.request('POST', '/api/sf-scans', body)[0], 400)

    def test_scan_lifecycle_findings_export_and_activity(self):
        self.login()
        status, scan, _ = self.request('POST', '/api/sf-scans', {'url': 'https://community.example.com', 'sample_size': 10, 'max_objects': 50})
        self.assertEqual(status, 201)
        self.assertEqual(scan['tool'], 'salesforce')
        self.wait_sf(scan['id'], lambda s: s['status'] == 'completed')
        scan = self.request('GET', '/api/sf-scans/' + scan['id'])[1]
        self.assertEqual(scan['verdict'], 'leaking')
        self.assertTrue(scan['is_salesforce'])
        prefix = '/api/sf-scans/' + scan['id']
        findings = self.request('GET', prefix + '/findings?readable=1')[1]
        account = next(f for f in findings['items'] if f['object'] == 'Account')
        self.assertEqual(account['record_count'], 42)
        self.assertEqual(len(account['samples']), 10)
        self.assertEqual(self.request('GET', prefix + '/findings?q=accou')[1]['items'][0]['object'], 'Account')
        self.assertIn('object,key_prefix', self.request('GET', prefix + '/export?format=csv')[1])
        self.assertEqual(self.request('GET', prefix + '/export?format=json')[1]['scan']['verdict'], 'leaking')
        self.assertEqual(self.request('GET', prefix + '/export?format=html')[0], 400)
        # The shared activity feed surfaces the Salesforce scan with its verdict.
        activity = self.request('GET', '/api/activity')[1]
        self.assertTrue(any(i['tool'] == 'salesforce' and i['verdict'] == 'leaking' for i in activity))
        self.assertEqual(self.request('DELETE', prefix)[0], 200)
        self.assertEqual(self.request('GET', prefix)[0], 404)

    def test_salesforce_page_is_served(self):
        self.assertEqual(self.request('GET', '/tools/salesforce')[0], 200)


if __name__ == '__main__':
    unittest.main()
