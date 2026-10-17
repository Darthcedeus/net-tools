"""Offline regressions for TLS options and conclusive detection outcomes."""
import socket
import ssl
import unittest
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch

from app.salesforce import Detector, DetectorError, FetchResult, guarded_fetch
from test_salesforce_discovery import BOOTSTRAP

ROOT = 'https://example.com'


class DiagnosticsTests(unittest.TestCase):
    def scan(self, fetch):
        with patch('app.salesforce._addresses_are_public'):
            return Detector(fetch=fetch).run(ROOT, lambda: False, lambda *_: None)

    def test_unreachable_is_inconclusive_and_diagnostics_are_bounded(self):
        def fail(*args, **kwargs):
            raise DetectorError('TLS certificate verification failed.')
        result = self.scan(fail)
        self.assertEqual(result['verdict'], 'unable_to_verify')
        self.assertFalse(result['is_salesforce'])
        self.assertGreater(result['discovery']['error_count'], 10)
        self.assertEqual(len(result['discovery']['errors']), 10)
        self.assertIn('TLS', result['discovery']['errors'][0]['message'])

    def test_fingerprint_survives_subsequent_pages_without_aura(self):
        def page(method, url, **kwargs):
            return FetchResult(200, {}, (BOOTSTRAP if url == ROOT else '<html>Other</html>').encode(), url)
        result = self.scan(page)
        self.assertEqual(result['verdict'], 'salesforce_detected')
        self.assertTrue(result['is_salesforce'])
        self.assertTrue(result['fingerprint'])
        self.assertFalse(result['aura_confirmed'])
        self.assertIsNone(result['aura_endpoint'])
        self.assertEqual(result['objects_checked'], 0)

    def test_complete_negative_and_http_failure_have_distinct_verdicts(self):
        for status, expected in [(404, 'not_salesforce'), (503, 'unable_to_verify'), (403, 'unable_to_verify')]:
            with self.subTest(status=status), patch('app.sf_discovery.COMMON_PATHS', ()):
                result = self.scan(lambda method, url, **kw: FetchResult(status, {}, b'<html>Page</html>', url))
                self.assertEqual(result['verdict'], expected)

    def test_discovery_limit_is_inconclusive(self):
        with patch('app.sf_discovery.MAX_REQUESTS', 1):
            result = self.scan(lambda method, url, **kw: FetchResult(200, {}, b'<html>Page</html>', url))
        self.assertEqual(result['verdict'], 'unable_to_verify')

    def test_diagnostics_remove_url_query_and_fragment(self):
        from app.sf_discovery import DomainDiscovery
        def fail(*args, **kwargs):
            raise DetectorError('Connection failed.')
        discovery = DomainDiscovery(ROOT, fail, lambda: False, (DetectorError,))
        discovery.request('GET', ROOT + '/login?token=secret#secret')
        self.assertEqual(discovery.details()['errors'][0]['url'], ROOT + '/login')


class TLSOptionsTests(unittest.TestCase):
    def test_default_is_verified_and_opt_in_only_changes_tls_context(self):
        for ignore in (False, True):
            with self.subTest(ignore=ignore), patch('app.salesforce._addresses_are_public') as public, \
                    patch('app.salesforce.urllib.request.build_opener') as build:
                response = build.return_value.open.return_value.__enter__.return_value
                response.status, response.headers, response.url = 200, {}, ROOT
                response.read.return_value = b'ok'
                guarded_fetch('GET', ROOT, **({'ignore_tls_errors': True} if ignore else {}))
                public.assert_called_once()
                handlers = build.call_args.args
                tls = [h for h in handlers if isinstance(h, urllib.request.HTTPSHandler)]
                self.assertEqual(len(tls), int(ignore))
                if ignore:
                    self.assertFalse(tls[0]._context.check_hostname)
                    self.assertEqual(tls[0]._context.verify_mode, ssl.CERT_NONE)

    def test_tls_and_timeout_failures_have_specific_safe_messages(self):
        for reason, message in [(ssl.SSLCertVerificationError(1, 'hostname mismatch'), 'TLS certificate verification failed'),
                                (socket.timeout(), 'timed out')]:
            with self.subTest(reason=reason), patch('app.salesforce._addresses_are_public'), \
                    patch('app.salesforce.urllib.request.build_opener') as build:
                build.return_value.open.side_effect = urllib.error.URLError(reason)
                with self.assertRaisesRegex(DetectorError, message):
                    guarded_fetch('GET', ROOT)

    def test_ignore_tls_still_rejects_private_addresses(self):
        with patch('app.salesforce._addresses_are_public', side_effect=ValueError('private')), \
                patch('app.salesforce.urllib.request.build_opener') as build:
            with self.assertRaisesRegex(ValueError, 'private'):
                guarded_fetch('GET', ROOT, ignore_tls_errors=True)
            build.assert_not_called()

    def test_option_reaches_discovery_and_object_requests(self):
        def fetch(method, url, **kwargs):
            self.assertTrue(kwargs['ignore_tls_errors'])
            return FetchResult(404, {}, b'', url)
        with patch('app.salesforce._addresses_are_public'), patch('app.salesforce.guarded_fetch', side_effect=fetch) as mocked:
            detector = Detector(ignore_tls_errors=True)
            detector.run(ROOT, lambda: False, lambda *_: None)
            discovery_calls = mocked.call_count
            detector._call(ROOT + '/aura', detector._context('siteforce:loginApp2', None, None), [], lambda: False)
            self.assertGreater(discovery_calls, 1)
            self.assertEqual(mocked.call_count, discovery_calls + 1)


class PersistenceAndOptionsTests(unittest.TestCase):
    def test_api_requires_boolean_tls_option_and_defaults_off(self):
        from app.server import Handler, APIError
        self.assertFalse(Handler.sf_options({})['ignore_tls_errors'])
        self.assertTrue(Handler.sf_options({'ignore_tls_errors': True})['ignore_tls_errors'])
        for value in ['true', 1, None, []]:
            with self.subTest(value=value), self.assertRaises(APIError):
                Handler.sf_options({'ignore_tls_errors': value})

    def test_activity_preserves_inconclusive_and_fingerprint_verdicts(self):
        import tempfile
        from pathlib import Path
        from app.store import Store
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'db.sqlite3')
            for i, verdict in enumerate(('unable_to_verify', 'salesforce_detected')):
                scan_id = str(i) * 32
                store.sf_create(scan_id, ROOT, {'ignore_tls_errors': True})
                store.sf_set_summary(scan_id, {'verdict': verdict, 'is_salesforce': i == 1,
                                              'discovery': {'errors': [{'message': 'TLS failed'}]}})
                store.sf_update(scan_id, status='completed')
                self.assertTrue(store.sf_get(scan_id)['options']['ignore_tls_errors'])
                self.assertEqual(store.sf_get(scan_id)['details']['discovery']['errors'][0]['message'], 'TLS failed')
            self.assertEqual({item['verdict'] for item in store.activity()}, {'unable_to_verify', 'salesforce_detected'})

    def test_runner_forwards_saved_tls_option_for_standalone_and_batch(self):
        import tempfile
        import threading
        import time
        from pathlib import Path
        from app.sf_runner import SalesforceRunner
        from app.store import Store
        for batch in (False, True):
            with self.subTest(batch=batch), tempfile.TemporaryDirectory() as directory:
                store = Store(Path(directory) / 'db.sqlite3')
                options = {'ignore_tls_errors': True}
                if batch:
                    source_id = 'a' * 32
                    store.create(source_id, 'example.com', {})
                    store.add_result(source_id, 'example.com', ['fixture'])
                    store.update(source_id, status='completed', finished=time.time())
                    scan_id = store.sf_batch_create('b' * 32, source_id, options)['items'][0]['id']
                else:
                    scan_id = 'c' * 32
                    store.sf_create(scan_id, ROOT, options)
                # Exercise the real worker's scan path without starting its queue thread.
                runner = SalesforceRunner.__new__(SalesforceRunner)
                runner.store, runner.detector = store, Detector()
                runner.lock = threading.RLock()
                runner.cancellations = {scan_id: threading.Event()}
                runner.stopping = threading.Event()
                runner.max_scan_seconds = 10
                with patch('app.sf_runner.Detector') as construct:
                    runner.run(scan_id)
                    self.assertTrue(construct.call_args.kwargs['ignore_tls_errors'])
                    construct.return_value.run.assert_called_once()
