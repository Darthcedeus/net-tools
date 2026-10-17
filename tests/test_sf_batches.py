import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from app.salesforce import Detector, FetchResult
from app.sf_runner import SalesforceRunner
from app.store import Store
import test_app as fixtures

sf_fetch = fixtures.sf_fetch


SOURCE = 'f' * 32
OPTIONS = {'sample_size': 2, 'max_objects': 1}


def source(store, hosts, source_id=SOURCE):
    store.create(source_id, 'example.com', {})
    for host in hosts:
        store.add_result(source_id, host, ['fixture'])
    store.update(source_id, status='completed', finished=time.time())


def wait_batch(store, batch_id, predicate=lambda b: b['status'] == 'completed'):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        batch = store.sf_batch_get(batch_id)
        if predicate(batch):
            return batch
        time.sleep(0.02)
    raise AssertionError(str(store.sf_batch_get(batch_id)))


class BatchStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / 'db.sqlite3'
        self.store = Store(self.path)

    def tearDown(self):
        self.directory.cleanup()

    def test_matching_snapshot_includes_results_beyond_first_page(self):
        source(self.store, [f'a{i:03d}.example.com' for i in range(210)] + ['z1.example.com', 'z2.example.com'])
        self.assertEqual(self.store.results(SOURCE)['items'][-1]['host'], 'a199.example.com')
        batch = self.store.sf_batch_create('b' * 32, SOURCE, OPTIONS, query='z')
        self.assertEqual([s['url'] for s in batch['items']], ['https://z1.example.com', 'https://z2.example.com'])
        self.store.add_result(SOURCE, 'z3.example.com', ['late'])
        self.assertEqual(self.store.sf_batch_get(batch['id'])['total'], 2)

    def test_selection_is_deduplicated_and_membership_enforced_atomically(self):
        source(self.store, ['api.example.com'])
        for hosts in [['other.example.com'], ['other.test']]:
            with self.assertRaisesRegex(ValueError, 'saved'):
                self.store.sf_batch_create('b' * 32, SOURCE, OPTIONS, hosts=hosts)
        self.assertEqual(self.store.sf_history(), [])
        batch = self.store.sf_batch_create('b' * 32, SOURCE, OPTIONS, hosts=['api.example.com'] * 2)
        self.assertEqual(batch['total'], 1)

    def test_oversized_and_empty_filters_never_create_partial_batches(self):
        source(self.store, [f'a{i}.example.com' for i in range(101)])
        for query in ['', 'missing', '%', '_']:
            with self.assertRaises(ValueError):
                self.store.sf_batch_create('b' * 32, SOURCE, OPTIONS, query=query)
        self.assertEqual(self.store.sf_batches(), [])
        self.assertEqual(self.store.sf_history(), [])

    def test_restart_keeps_pending_batch_hosts_and_interrupts_active_host(self):
        source(self.store, ['a.example.com', 'b.example.com', 'c.example.com'])
        batch = self.store.sf_batch_create('b' * 32, SOURCE, OPTIONS)
        self.store.sf_update(batch['items'][0]['id'], status='running', started=time.time())
        reopened = Store(self.path)
        batch = reopened.sf_batch_get(batch['id'])
        self.assertEqual((batch['interrupted'], batch['queued']), (1, 2))
        with patch('app.salesforce._addresses_are_public'):
            runner = SalesforceRunner(reopened, Detector(fetch=sf_fetch()))
            try:
                batch = wait_batch(reopened, batch['id'])
                self.assertEqual((batch['completed'], batch['interrupted']), (2, 1))
            finally:
                runner.close()

    def test_retention_keeps_batch_children_and_source_discovery(self):
        source(self.store, ['a.example.com', 'b.example.com'])
        batch = self.store.sf_batch_create('b' * 32, SOURCE, OPTIONS)
        self.store.sf_batch_cancel(batch['id'])
        for i in range(102):
            self.store.sf_create(f'{i:032x}', 'https://example.com', OPTIONS)
            self.store.sf_update(f'{i:032x}', status='completed')
            self.store.create(f'{i:032x}', 'other.test', {})
            self.store.update(f'{i:032x}', status='completed')
        self.assertEqual(self.store.sf_batch_get(batch['id'])['total'], 2)
        self.assertIsNotNone(self.store.get(SOURCE))
        self.assertEqual(len(self.store.sf_history()), 102)

    def test_ten_finished_batches_are_retained_and_old_children_are_removed(self):
        source(self.store, ['a.example.com'])
        children = []
        for i in range(12):
            batch = self.store.sf_batch_create(f'{i:032x}', SOURCE, OPTIONS)
            children.append(batch['items'][0]['id'])
            self.store.sf_batch_cancel(batch['id'])
        self.assertEqual(len(self.store.sf_batches()), 10)
        self.assertIsNone(self.store.sf_get(children[0]))
        self.assertIsNotNone(self.store.sf_get(children[-1]))
        self.store.delete(SOURCE)
        self.assertEqual(self.store.sf_history(), [])

    def test_activity_has_one_batch_entry_instead_of_every_child(self):
        source(self.store, ['a.example.com', 'b.example.com'])
        batch = self.store.sf_batch_create('b' * 32, SOURCE, OPTIONS)
        items = [item for item in self.store.activity() if item['tool'] == 'salesforce']
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['batch_id'], batch['id'])

    def test_existing_salesforce_database_is_migrated_without_losing_findings(self):
        legacy = Path(self.directory.name) / 'legacy.sqlite3'
        with sqlite3.connect(legacy) as db:
            db.execute("CREATE TABLE sf_scans (id TEXT PRIMARY KEY,url TEXT NOT NULL,status TEXT NOT NULL,created REAL NOT NULL,started REAL,finished REAL,options TEXT NOT NULL,error TEXT,verdict TEXT,is_salesforce INTEGER NOT NULL DEFAULT 0,aura_endpoint TEXT,details TEXT NOT NULL DEFAULT '{}',count INTEGER NOT NULL DEFAULT 0)")
            db.execute("INSERT INTO sf_scans(id,url,status,created,options,count) VALUES ('old','https://example.com','completed',1,'{}',1)")
        migrated = Store(legacy)
        migrated.sf_add_finding('old', {'object': 'Account', 'readable': True, 'samples': [{'Id': '001'}]})
        self.assertIsNone(migrated.sf_get('old')['batch_id'])
        self.assertEqual(migrated.sf_findings('old')['items'][0]['samples'], [{'Id': '001'}])


class RunnerFlowTests(unittest.TestCase):
    setUp = BatchStoreTests.setUp
    tearDown = BatchStoreTests.tearDown

    def test_more_than_five_hosts_drain_without_queue_truncation(self):
        source(self.store, [f'a{i:02d}.example.com' for i in range(12)])
        with patch('app.salesforce._addresses_are_public'):
            runner = SalesforceRunner(self.store, Detector(fetch=sf_fetch()))
            try:
                batch = runner.submit_batch(SOURCE, OPTIONS)
                batch = wait_batch(self.store, batch['id'])
                self.assertEqual((batch['total'], batch['completed']), (12, 12))
            finally:
                runner.close()

    def test_cancel_stops_active_and_unscheduled_hosts(self):
        source(self.store, [f'a{i:02d}.example.com' for i in range(12)])
        started, release = threading.Event(), threading.Event()
        calls = []

        def fetch(method, url, **kwargs):
            calls.append(url); started.set(); release.wait(3)
            return FetchResult(404, {}, b'<html>Not found</html>', url)

        with patch('app.salesforce._addresses_are_public'):
            runner = SalesforceRunner(self.store, Detector(fetch=fetch))
            try:
                batch = runner.submit_batch(SOURCE, OPTIONS)
                self.assertTrue(started.wait(2))
                runner.cancel_batch(batch['id']); release.set()
                batch = wait_batch(self.store, batch['id'], lambda b: b['status'] == 'cancelled')
                self.assertEqual(batch['cancelled'], 12)
                self.assertEqual(len(calls), 1)
            finally:
                release.set(); runner.close()

    def test_private_target_failure_does_not_stop_other_hosts(self):
        source(self.store, ['a.example.com', 'private.example.com', 'z.example.com'])

        def public(host, port):
            if host.startswith('private.'):
                raise ValueError('The target resolves to a private or reserved address.')

        with patch('app.salesforce._addresses_are_public', side_effect=public):
            runner = SalesforceRunner(self.store, Detector(fetch=sf_fetch()))
            try:
                batch = runner.submit_batch(SOURCE, OPTIONS)
                batch = wait_batch(self.store, batch['id'])
                self.assertEqual((batch['completed'], batch['failed']), (2, 1))
            finally:
                runner.close()


class BatchAPITests(unittest.TestCase):
    setUp = fixtures.SalesforceAPITests.setUp
    tearDown = fixtures.SalesforceAPITests.tearDown
    request = fixtures.SalesforceAPITests.request
    login = fixtures.SalesforceAPITests.login

    def seed(self, hosts=None):
        source(self.app.store, hosts or ['api.example.com', 'support.example.com'])
        return f'/api/scans/{SOURCE}/sf-batches'

    def test_authenticated_batch_lifecycle_links_exports_and_delete(self):
        path = self.seed(); self.login()
        status, batch, _ = self.request('POST', path, {**OPTIONS, 'hosts': ['support.example.com']})
        self.assertEqual(status, 201)
        batch = wait_batch(self.app.store, batch['id'])
        self.assertEqual((batch['total'], batch['completed']), (1, 1))
        child = batch['items'][0]
        self.assertEqual(self.request('GET', '/api/sf-scans/' + child['id'])[1]['batch_id'], batch['id'])
        self.assertEqual(self.request('GET', path)[1][0]['id'], batch['id'])
        self.assertEqual(self.request('GET', '/api/sf-batches/' + batch['id'] + '/export')[1]['total'], 1)
        self.assertEqual(self.request('DELETE', '/api/sf-scans/' + child['id'])[0], 409)
        self.assertEqual(self.request('DELETE', '/api/sf-batches/' + batch['id'])[0], 200)
        self.assertEqual(self.request('GET', '/api/sf-scans/' + child['id'])[0], 404)

    def test_auth_csrf_origin_membership_and_option_validation(self):
        path = self.seed()
        self.assertEqual(self.request('POST', path, {})[0], 401)
        self.assertEqual(self.request('GET', '/api/sf-batches/' + 'a' * 32)[0], 401)
        self.login()
        self.assertEqual(self.request('POST', path, {}, {'X-CSRF-Token': ''})[0], 403)
        self.assertEqual(self.request('POST', path, {}, {'Origin': 'https://other.test'})[0], 403)
        for data in [{'hosts': []}, {'hosts': 'api.example.com'}, {'hosts': ['other.example.com']},
                     {'hosts': ['https://api.example.com']}, {'hosts': ['api.example.com'], 'q': 'api'},
                     {'q': 42}, {'sample_size': True}, {'max_objects': 201}]:
            with self.subTest(data=data):
                self.assertEqual(self.request('POST', path, data)[0], 400)
        self.assertEqual(self.app.store.sf_batches(), [])

    def test_running_discovery_cannot_start_batch(self):
        path = self.seed(); self.login(); self.app.store.update(SOURCE, status='running')
        self.assertEqual(self.request('POST', path, {})[0], 409)

    def test_matching_filter_uses_all_pages(self):
        path = self.seed([f'a{i:03d}.example.com' for i in range(210)] + ['z.example.com']); self.login()
        self.assertEqual(self.request('POST', path, {})[0], 400)
        status, batch, _ = self.request('POST', path, {**OPTIONS, 'q': 'z.'})
        self.assertEqual(status, 201)
        self.assertEqual(batch['total'], 1)
        self.assertEqual(batch['items'][0]['url'], 'https://z.example.com')

    def test_cancel_and_source_deletion_wait_for_running_host(self):
        path = self.seed(); self.login()
        started, release = threading.Event(), threading.Event()

        def fetch(method, url, **kwargs):
            started.set(); release.wait(3)
            return FetchResult(404, {}, b'<html>Not found</html>', url)

        self.app.sf_runner.detector = Detector(fetch=fetch)
        try:
            status, batch, _ = self.request('POST', path, OPTIONS)
            self.assertEqual(status, 201); self.assertTrue(started.wait(2))
            self.assertEqual(self.request('DELETE', '/api/scans/' + SOURCE)[0], 409)
            self.assertEqual(self.request('DELETE', '/api/sf-batches/' + batch['id'])[0], 409)
            self.assertEqual(self.request('POST', '/api/sf-batches/' + batch['id'] + '/cancel', {})[0], 200)
            self.assertEqual(self.request('DELETE', '/api/scans/' + SOURCE)[0], 409)
            release.set(); wait_batch(self.app.store, batch['id'], lambda value: value['status'] == 'cancelled')
            self.assertEqual(self.request('DELETE', '/api/scans/' + SOURCE)[0], 200)
            self.assertEqual(self.request('GET', '/api/sf-batches/' + batch['id'])[0], 404)
        finally:
            release.set()
