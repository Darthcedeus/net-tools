import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from app.store import Store
import test_app as fixtures


SOURCE, SINGLE, BATCH, ACTIVE = 'a' * 32, 'b' * 32, 'c' * 32, 'd' * 32


def seed(store):
    store.create(SOURCE, 'example.com', {})
    store.add_result(SOURCE, 'support.example.com', ['fixture'])
    store.update(SOURCE, status='completed', finished=time.time())
    store.sf_create(SINGLE, 'https://single.example.com', {})
    store.sf_update(SINGLE, status='completed', finished=time.time())
    batch = store.sf_batch_create(BATCH, SOURCE, {})
    child = batch['items'][0]['id']
    store.sf_add_finding(child, {'object': 'Account', 'readable': True, 'samples': [{'Id': '001'}]})
    store.sf_update(child, status='completed', finished=time.time())
    return child


class ActivityDeletionStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / 'history.sqlite3')
        self.child = seed(self.store)

    def tearDown(self):
        self.directory.cleanup()

    def test_mixed_selection_with_parent_and_batch_cascades(self):
        deleted = self.store.delete_activities([{'kind': 'subdomains', 'id': SOURCE},
                                               {'kind': 'salesforce_batch', 'id': BATCH},
                                               {'kind': 'salesforce', 'id': SINGLE}])
        self.assertEqual(deleted['deleted'], 3)
        self.assertEqual(self.store.activity(), [])
        self.assertIsNone(self.store.sf_get(self.child))
        self.assertEqual(self.store.sf_findings(self.child)['total'], 0)

    def test_active_scan_rejects_entire_selection(self):
        self.store.sf_create(ACTIVE, 'https://active.example.com', {})
        for status in ('queued', 'running'):
            self.store.sf_update(ACTIVE, status=status)
            with self.assertRaisesRegex(ValueError, 'Nothing was deleted'):
                self.store.delete_activities([{'kind': 'salesforce', 'id': SINGLE}, {'kind': 'salesforce', 'id': ACTIVE}])
            self.assertIsNotNone(self.store.sf_get(SINGLE))

    def test_active_batch_protects_its_finished_source(self):
        self.store.sf_update(self.child, status='running')
        activity = {item['id']: item for item in self.store.activity()}
        self.assertFalse(activity[SOURCE]['deletable'])
        self.assertFalse(activity[BATCH]['deletable'])
        self.assertTrue(activity[SINGLE]['deletable'])
        self.assertEqual(activity[BATCH]['delete_kind'], 'salesforce_batch')
        for kind, activity_id in [('subdomains', SOURCE), ('salesforce_batch', BATCH)]:
            with self.assertRaises(ValueError):
                self.store.delete_activities([{'kind': 'salesforce', 'id': SINGLE}, {'kind': kind, 'id': activity_id}])
            self.assertIsNotNone(self.store.sf_get(SINGLE))

    def test_missing_item_rejects_whole_selection(self):
        with self.assertRaisesRegex(ValueError, 'history changed'):
            self.store.delete_activities([{'kind': 'salesforce', 'id': SINGLE}, {'kind': 'subdomains', 'id': ACTIVE}])
        self.assertIsNotNone(self.store.sf_get(SINGLE))

    def test_individual_batch_child_cannot_be_deleted_as_activity(self):
        with self.assertRaisesRegex(ValueError, 'batch instead'):
            self.store.delete_activities([{'kind': 'salesforce', 'id': self.child}])
        self.assertIsNotNone(self.store.sf_get(self.child))

    def test_invalid_and_duplicate_selections_do_not_change_history(self):
        for items in [[], [{}], [{'kind': 'bad', 'id': SINGLE}], [{'kind': 'salesforce', 'id': '../x'}],
                      [{'kind': 'salesforce', 'id': SINGLE}] * 2, [{'kind': 'salesforce', 'id': SINGLE}] * 501]:
            with self.subTest(items=items[:2]), self.assertRaises(ValueError):
                self.store.delete_activities(items)
        self.assertEqual(len(self.store.activity()), 3)

    def test_id_namespaces_can_overlap(self):
        self.store.sf_create(SOURCE, 'https://duplicate.example.com', {})
        self.store.sf_update(SOURCE, status='completed')
        self.store.delete_activities([{'kind': 'subdomains', 'id': SOURCE}, {'kind': 'salesforce', 'id': SOURCE}])
        self.assertIsNone(self.store.get(SOURCE))
        self.assertIsNone(self.store.sf_get(SOURCE))
        self.assertIsNotNone(self.store.sf_get(SINGLE))

    def test_sql_error_rolls_back_prior_deletes(self):
        with self.store.connect() as db:
            db.execute("CREATE TRIGGER fail_delete BEFORE DELETE ON scans BEGIN SELECT RAISE(ABORT,'fixture failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.delete_activities([{'kind': 'salesforce', 'id': SINGLE}, {'kind': 'subdomains', 'id': SOURCE}])
        self.assertIsNotNone(self.store.sf_get(SINGLE))
        self.assertIsNotNone(self.store.sf_get(self.child))


class ActivityDeletionAPITests(unittest.TestCase):
    setUp = fixtures.SalesforceAPITests.setUp
    tearDown = fixtures.SalesforceAPITests.tearDown
    request = fixtures.SalesforceAPITests.request
    login = fixtures.SalesforceAPITests.login

    def test_auth_origin_csrf_and_validation(self):
        self.assertEqual(self.request('POST', '/api/activity/delete', {'items': []})[0], 401)
        self.login()
        self.assertEqual(self.request('POST', '/api/activity/delete', {'items': []}, {'X-CSRF-Token': ''})[0], 403)
        self.assertEqual(self.request('POST', '/api/activity/delete', {'items': []}, {'Origin': 'https://other.test'})[0], 403)
        for items in [None, [], 'all', [{'kind': 'unknown', 'id': SINGLE}], [{'kind': 'salesforce', 'id': True}]]:
            self.assertEqual(self.request('POST', '/api/activity/delete', {'items': items})[0], 400)

    def test_mixed_api_deletion_and_activity_metadata(self):
        self.login()
        with self.app.sf_runner.lock:
            child = seed(self.app.store)
        activities = self.request('GET', '/api/activity')[1]
        self.assertTrue(all(item['deletable'] for item in activities))
        items = [{'kind': item['delete_kind'], 'id': item['id']} for item in activities]
        status, result, _ = self.request('POST', '/api/activity/delete', {'items': items})
        self.assertEqual(status, 200)
        self.assertEqual(result['deleted'], 3)
        self.assertEqual(self.request('GET', '/api/activity')[1], [])
        self.assertEqual(self.request('GET', '/api/sf-scans/' + child)[0], 404)

    def test_changed_selection_returns_conflict_without_partial_deletion(self):
        self.login()
        with self.app.sf_runner.lock:
            seed(self.app.store)
        items = [{'kind': 'salesforce', 'id': SINGLE}, {'kind': 'subdomains', 'id': ACTIVE}]
        self.assertEqual(self.request('POST', '/api/activity/delete', {'items': items})[0], 409)
        self.assertIsNotNone(self.app.store.sf_get(SINGLE))
