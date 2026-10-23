import http.client
import json
import os
import socket
import ssl
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from app.reach_runner import ReachabilityRunner
from app.reachability import _classify_error, probe_host
from app.server import Application, Server
from app.store import Store, MAX_REACH_HOSTS
from test_app import HASH, PASSWORD, FIXTURE, fixture_addresses

SOURCE = 'f' * 32
OPTIONS = {'timeout': 5, 'concurrency': 4}


def source(store, hosts, source_id=SOURCE):
    store.create(source_id, 'example.com', {})
    for host in hosts:
        store.add_result(source_id, host, ['fixture'])
    store.update(source_id, status='completed', finished=time.time())


def fake_prober(reachable_predicate=lambda host: not host.startswith('down.'), gate=None):
    def prober(host, timeout):
        if gate is not None:
            gate.wait(3)
        up = reachable_predicate(host)
        return {'host': host, 'reachable': up, 'scheme': 'https' if up else None,
                'status': 200 if up else None, 'server': 'nginx' if up else None,
                'final_url': f'https://{host}/' if up else None,
                'error': None if up else 'refused', 'elapsed_ms': 3, 'details': {}}
    return prober


def wait_batch(store, batch_id, predicate=lambda b: b['status'] == 'completed', timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        batch = store.reach_batch_get(batch_id)
        if batch and predicate(batch):
            return batch
        time.sleep(0.02)
    raise AssertionError(str(store.reach_batch_get(batch_id)))


class ProbeTests(unittest.TestCase):
    def test_https_is_preferred_and_summary_reflects_served_scheme(self):
        def probe(scheme, host):
            return {'ok': True, 'status': 200, 'server': 'nginx', 'final_url': f'{scheme}://{host}/', 'location': None}
        result = probe_host('api.example.com', probe=probe)
        self.assertTrue(result['reachable'])
        self.assertEqual(result['scheme'], 'https')
        self.assertEqual(result['status'], 200)
        self.assertEqual(result['server'], 'nginx')

    def test_falls_back_to_http_when_https_fails(self):
        def probe(scheme, host):
            if scheme == 'https':
                return {'ok': False, 'error': 'tls_error'}
            return {'ok': True, 'status': 301, 'server': None, 'final_url': f'http://{host}/', 'location': 'https://x/'}
        result = probe_host('api.example.com', probe=probe)
        self.assertTrue(result['reachable'])
        self.assertEqual(result['scheme'], 'http')
        self.assertEqual(result['status'], 301)

    def test_unreachable_records_first_error_and_no_scheme(self):
        def probe(scheme, host):
            return {'ok': False, 'error': 'timeout' if scheme == 'https' else 'refused'}
        result = probe_host('down.example.com', probe=probe)
        self.assertFalse(result['reachable'])
        self.assertIsNone(result['scheme'])
        self.assertEqual(result['error'], 'timeout')

    def test_guard_rejects_loopback_without_network(self):
        # localhost resolves to a loopback address, which the public-address
        # guard refuses, so no external connection is attempted.
        result = probe_host('localhost', timeout=1)
        self.assertFalse(result['reachable'])
        self.assertEqual(result['details']['https']['error'], 'dns_error')

    def test_error_classification(self):
        self.assertEqual(_classify_error(socket.timeout()), 'timeout')
        self.assertEqual(_classify_error(ConnectionRefusedError()), 'refused')
        self.assertEqual(_classify_error(ssl.SSLCertVerificationError()), 'tls_cert_error')
        self.assertEqual(_classify_error(ssl.SSLError()), 'tls_error')
        self.assertEqual(_classify_error(socket.gaierror()), 'dns_error')


class RunnerStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / 'db.sqlite3')

    def tearDown(self):
        self.directory.cleanup()

    def test_batch_runs_and_counts_reachable_hosts(self):
        source(self.store, ['up.example.com', 'down.example.com', 'up2.example.com'])
        runner = ReachabilityRunner(self.store, prober=fake_prober())
        self.addCleanup(runner.close)
        batch = runner.submit_batch(SOURCE, OPTIONS, hosts=['up.example.com', 'down.example.com', 'up2.example.com'])
        final = wait_batch(self.store, batch['id'])
        self.assertEqual(final['done'], 3)
        self.assertEqual(final['reachable'], 2)
        self.assertEqual(final['unreachable'], 1)
        by_host = {item['host']: item for item in final['items']}
        self.assertTrue(by_host['up.example.com']['reachable'])
        self.assertEqual(by_host['up.example.com']['scheme'], 'https')
        self.assertFalse(by_host['down.example.com']['reachable'])
        self.assertEqual(by_host['down.example.com']['error'], 'refused')

    def test_matching_query_snapshots_hosts(self):
        source(self.store, ['shop.example.com', 'blog.example.com', 'api.example.com'])
        batch = self.store.reach_batch_create('b' * 32, SOURCE, OPTIONS, query='op')
        self.assertEqual(sorted(i['host'] for i in batch['items']), ['shop.example.com'])

    def test_membership_and_scope_enforced(self):
        source(self.store, ['api.example.com'])
        with self.assertRaisesRegex(ValueError, 'saved'):
            self.store.reach_batch_create('b' * 32, SOURCE, OPTIONS, hosts=['other.example.com'])
        with self.assertRaises(ValueError):
            self.store.reach_batch_create('b' * 32, SOURCE, OPTIONS, query='missing')
        self.assertEqual(self.store.reach_batches(), [])

    def test_only_one_active_batch(self):
        source(self.store, ['h0.example.com', 'h1.example.com', 'h2.example.com'])
        gate = threading.Event()
        runner = ReachabilityRunner(self.store, prober=fake_prober(gate=gate))
        self.addCleanup(runner.close)
        batch = runner.submit_batch(SOURCE, OPTIONS, hosts=['h0.example.com', 'h1.example.com', 'h2.example.com'])
        wait_batch(self.store, batch['id'], lambda b: b['status'] == 'running', timeout=4)
        with self.assertRaisesRegex(ValueError, 'already active'):
            runner.submit_batch(SOURCE, OPTIONS, hosts=['h0.example.com'])
        gate.set()
        wait_batch(self.store, batch['id'])

    def test_cancel_stops_batch(self):
        source(self.store, [f'h{i}.example.com' for i in range(8)])
        gate = threading.Event()
        runner = ReachabilityRunner(self.store, prober=fake_prober(gate=gate))
        self.addCleanup(runner.close)
        batch = runner.submit_batch(SOURCE, OPTIONS, hosts=[f'h{i}.example.com' for i in range(8)])
        wait_batch(self.store, batch['id'], lambda b: b['status'] == 'running', timeout=4)
        runner.cancel_batch(batch['id'])
        gate.set()
        final = wait_batch(self.store, batch['id'], lambda b: b['status'] == 'cancelled')
        self.assertEqual(final['status'], 'cancelled')

    def test_source_protected_and_cascade_delete(self):
        source(self.store, ['h0.example.com', 'h1.example.com'])
        gate = threading.Event()
        runner = ReachabilityRunner(self.store, prober=fake_prober(gate=gate))
        self.addCleanup(runner.close)
        batch = runner.submit_batch(SOURCE, OPTIONS, hosts=['h0.example.com', 'h1.example.com'])
        wait_batch(self.store, batch['id'], lambda b: b['status'] == 'running', timeout=4)
        activity = {item['tool']: item for item in self.store.activity()}
        self.assertFalse(activity['subdomains']['deletable'])
        self.assertEqual(activity['reachability']['delete_kind'], 'reachability_batch')
        gate.set()
        wait_batch(self.store, batch['id'])
        self.store.delete(SOURCE)
        self.assertIsNone(self.store.reach_batch_get(batch['id']))

    def test_delete_activities_blocks_active_reach_batch(self):
        source(self.store, ['h0.example.com'])
        gate = threading.Event()
        runner = ReachabilityRunner(self.store, prober=fake_prober(gate=gate))
        self.addCleanup(runner.close)
        batch = runner.submit_batch(SOURCE, OPTIONS, hosts=['h0.example.com'])
        wait_batch(self.store, batch['id'], lambda b: b['status'] == 'running', timeout=4)
        with self.assertRaisesRegex(ValueError, 'Cancel active'):
            self.store.delete_activities([{'kind': 'reachability_batch', 'id': batch['id']}])
        with self.assertRaisesRegex(ValueError, 'Cancel active'):
            self.store.delete_activities([{'kind': 'subdomains', 'id': SOURCE}])
        gate.set()
        wait_batch(self.store, batch['id'])

    def test_pending_hosts_resume_after_restart(self):
        source(self.store, ['h0.example.com', 'h1.example.com', 'h2.example.com'])
        # Create a batch that is interrupted mid-run: mark it running with one
        # host already done, then re-open the store to simulate a restart.
        self.store.reach_batch_create('b' * 32, SOURCE, OPTIONS, hosts=['h0.example.com', 'h1.example.com', 'h2.example.com'])
        self.store.reach_start('b' * 32)
        self.store.reach_record('b' * 32, {'host': 'h0.example.com', 'reachable': True, 'scheme': 'https',
                                           'status': 200, 'server': None, 'final_url': None, 'error': None,
                                           'elapsed_ms': 1, 'details': {}})
        restarted = Store(self.store.path)
        batch = restarted.reach_batch_get('b' * 32, items=False)
        self.assertEqual(batch['status'], 'queued')
        runner = ReachabilityRunner(restarted, prober=fake_prober())
        self.addCleanup(runner.close)
        final = wait_batch(restarted, 'b' * 32)
        self.assertEqual(final['done'], 3)
        self.assertEqual(final['reachable'], 3)


class ReachAPITests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.environment = patch.dict(os.environ, {'APP_ORIGIN': 'http://localhost:8080', 'APP_PASSWORD_HASH': HASH, 'DATA_DIR': self.directory.name, 'SUBFINDER_BIN': str(FIXTURE)})
        self.environment.start()
        self.dns_patch = patch('app.runner.resolve_host', side_effect=fixture_addresses)
        self.dns_patch.start()
        self.app = Application()
        self.app.reach_runner.prober = fake_prober()
        self.server = Server(('127.0.0.1', 0), self.app)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start(); self.cookie = ''; self.csrf = ''

    def tearDown(self):
        self.server.shutdown(); self.app.runner.close(); self.app.sf_runner.close(); self.app.reach_runner.close(); self.server.server_close()
        self.environment.stop(); self.directory.cleanup(); self.dns_patch.stop()

    def request(self, method, path, data=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        body = json.dumps(data) if data is not None else None
        default = {'Origin': self.app.origin, 'Content-Type': 'application/json', 'Cookie': self.cookie, 'X-CSRF-Token': self.csrf}
        connection.request(method, path, body=body, headers={**default, **(headers or {})})
        response = connection.getresponse(); raw = response.read().decode(); status = response.status
        response_headers = dict(response.getheaders()); connection.close()
        return status, json.loads(raw) if 'application/json' in response_headers.get('Content-Type', '') else raw, response_headers

    def login(self):
        status, data, headers = self.request('POST', '/api/login', {'password': PASSWORD})
        self.cookie = headers['Set-Cookie'].split(';')[0]; self.csrf = data['csrf']

    def seed(self, hosts):
        self.app.store.create(SOURCE, 'example.com', {})
        for host in hosts:
            self.app.store.add_result(SOURCE, host, ['fixture'])
        self.app.store.update(SOURCE, status='completed', finished=time.time())

    def wait(self, batch_id):
        return wait_batch(self.app.store, batch_id)

    def test_create_poll_and_export_batch(self):
        self.login()
        self.seed(['up.example.com', 'down.example.com'])
        status, batch, _ = self.request('POST', f'/api/scans/{SOURCE}/reach-batches', {'hosts': ['up.example.com', 'down.example.com']})
        self.assertEqual(status, 201)
        self.wait(batch['id'])
        status, fetched, _ = self.request('GET', f'/api/reach-batches/{batch["id"]}')
        self.assertEqual(status, 200)
        self.assertEqual(fetched['reachable'], 1)
        self.assertEqual(fetched['unreachable'], 1)
        status, csv_body, headers = self.request('GET', f'/api/reach-batches/{batch["id"]}/export?format=csv')
        self.assertEqual(status, 200)
        self.assertIn('text/csv', headers['Content-Type'])
        self.assertIn('up.example.com', csv_body)
        self.assertIn('reachability', headers['Content-Disposition'])

    def test_rejects_second_active_batch_with_conflict(self):
        self.login()
        self.seed(['a.example.com', 'b.example.com'])
        gate = threading.Event()
        self.app.reach_runner.prober = fake_prober(gate=gate)
        status, batch, _ = self.request('POST', f'/api/scans/{SOURCE}/reach-batches', {'hosts': ['a.example.com', 'b.example.com']})
        self.assertEqual(status, 201)
        wait_batch(self.app.store, batch['id'], lambda b: b['status'] == 'running', timeout=4)
        status, body, _ = self.request('POST', f'/api/scans/{SOURCE}/reach-batches', {'hosts': ['a.example.com']})
        self.assertEqual(status, 409)
        self.assertIn('already active', body['error'])
        gate.set(); self.wait(batch['id'])

    def test_validation_rejects_bad_options(self):
        self.login()
        self.seed(['a.example.com'])
        status, body, _ = self.request('POST', f'/api/scans/{SOURCE}/reach-batches', {'hosts': ['a.example.com'], 'timeout': 99})
        self.assertEqual(status, 400)
        status, _, _ = self.request('POST', f'/api/scans/{SOURCE}/reach-batches', {'hosts': ['a.example.com'] * (MAX_REACH_HOSTS + 1)})
        self.assertEqual(status, 400)


if __name__ == '__main__':
    unittest.main()
