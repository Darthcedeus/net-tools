import http.client
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from app.runner import Runner
from app.security import hash_password, normalize_domain, verify_password
from app.server import Application, Server
from app.store import Store

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests' / 'fixtures' / 'subfinder.py'
FIXTURE.chmod(0o755)
PASSWORD = 'test-password-long-enough'
HASH = hash_password(PASSWORD)
OPTIONS = {'timeout': 5, 'max_time': 1, 'rate_limit': 10, 'all_sources': False, 'recursive': False}


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
        self.runner = Runner(self.store, str(FIXTURE))

    def tearDown(self):
        self.runner.close(); self.directory.cleanup()

    def test_streaming_merge_normalization_and_scope(self):
        scan = self.runner.submit('example.com', OPTIONS)
        completed = wait_for(self.store, scan['id'], lambda s: s['status'] == 'completed')
        self.assertEqual(completed['count'], 5)
        row = self.store.results(scan['id'])['items'][0]
        self.assertEqual(row['host'], 'api.example.com')
        self.assertEqual(row['sources'], ['another', 'crtsh', 'hackertarget'])

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
        self.app = Application()
        self.server = Server(('127.0.0.1', 0), self.app)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start(); self.cookie = ''; self.csrf = ''

    def tearDown(self):
        self.server.shutdown(); self.app.runner.close(); self.server.server_close()
        self.environment.stop(); self.directory.cleanup()

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
        self.assertEqual(self.request('GET', prefix + '/results?q=%25')[1]['total'], 0)
        self.assertEqual(len(self.request('GET', prefix + '/export?format=txt')[1].splitlines()), 5)
        self.assertEqual(self.request('GET', prefix + '/export?format=txt&q=api')[1], 'api.example.com\n')
        self.assertIn('subdomain,sources', self.request('GET', prefix + '/export?format=csv')[1])
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
        for _ in range(10):
            self.assertEqual(self.request('POST', '/api/login', {'password': 'bad'})[0], 401)
        self.assertEqual(self.request('POST', '/api/login', {'password': PASSWORD})[0], 429)

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


if __name__ == '__main__':
    unittest.main()
