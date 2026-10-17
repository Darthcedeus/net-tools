"""Offline regressions for community paths, Aura replies and redirects."""
import json
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs

from app.salesforce import Detector, FetchResult, guarded_fetch, safe_target, _Redirect


ORIGIN = 'https://community.example.com'
BOOTSTRAP = ('<script>"fwuid":"BOOTSTRAP_FW",'
             '"app":"siteforce:communityApp",'
             '"APPLICATION@markup://siteforce:communityApp":"APPID"</script>')


class Community:
    def __init__(self, endpoint, landing_url=None, bootstrap='', canonical=None):
        self.endpoint = endpoint
        self.landing_url = landing_url
        self.bootstrap = bootstrap
        self.canonical = canonical
        self.calls = []

    def __call__(self, method, url, headers=None, data=None, **kwargs):
        self.calls.append((method, url, data))
        if method == 'GET':
            return FetchResult(200, {}, self.bootstrap.encode(), self.landing_url or url)
        if url != self.endpoint and url != self.canonical:
            # A catch-all serves Salesforce HTML even for invalid endpoints.
            return FetchResult(200, {}, BOOTSTRAP.encode(), url)
        params = parse_qs(data.decode())
        action = json.loads(params['message'][0])['actions'][0]
        context = json.loads(params['aura.context'][0])
        final_url = self.canonical or url
        if context['fwuid'] != 'SERVER_FW' and context['fwuid'] != 'BOOTSTRAP_FW':
            body = {'exceptionEvent': True, 'event': {'descriptor': 'markup://aura:clientOutOfSync'},
                    'newFwuid': 'SERVER_FW'}
        else:
            value = ({'apiNamesToKeyPrefixes': {'Account': '001'}}
                     if action['id'] == '1;a' else {'totalCount': 1, 'result': [{'Id': '001'}]})
            # Real replies need not echo the action descriptor.
            body = {'actions': [{'id': action['id'], 'state': 'SUCCESS', 'returnValue': value}]}
        return FetchResult(200, {}, json.dumps(body).encode(), final_url)


class DiscoveryTests(unittest.TestCase):
    def scan(self, fetch, target=ORIGIN):
        with patch('app.salesforce._addresses_are_public'):
            return Detector(fetch=fetch, max_objects=1).run(target, lambda: False, lambda *_: None)

    def test_preserves_path_query_and_removes_fragment(self):
        with patch('app.salesforce._addresses_are_public'):
            self.assertEqual(safe_target('community.example.com/partners/s/?lang=en#top'),
                             ORIGIN + '/partners/s/?lang=en')

    def test_supplied_nested_community_path(self):
        endpoint = ORIGIN + '/regional/partners/s/sfsites/aura'
        fetch = Community(endpoint, bootstrap=BOOTSTRAP)
        result = self.scan(fetch, ORIGIN + '/regional/partners/s/login')
        self.assertEqual(result['aura_endpoint'], endpoint)
        self.assertEqual(result['verdict'], 'leaking')
        self.assertEqual(fetch.calls[0][:2], ('GET', ORIGIN + '/regional/partners/s/login'))
        self.assertEqual(fetch.calls[1][1], endpoint)
        self.assertEqual(parse_qs(fetch.calls[1][2].decode())['aura.pageURI'], ['/regional/partners/s'])

    def test_community_prefix_from_landing_redirect(self):
        endpoint = ORIGIN + '/partners/s/sfsites/aura'
        fetch = Community(endpoint, landing_url=ORIGIN + '/partners/s/', bootstrap=BOOTSTRAP)
        self.assertEqual(self.scan(fetch)['aura_endpoint'], endpoint)

    def test_nested_community_prefix_from_html_link(self):
        endpoint = ORIGIN + '/regional/partners/s/aura'
        fetch = Community(endpoint, bootstrap=BOOTSTRAP + '<a href="/regional/partners/s/">Community</a>')
        self.assertEqual(self.scan(fetch)['aura_endpoint'], endpoint)

    def test_dummy_context_and_expected_fwuid_support_non_word_characters(self):
        detector = Detector()
        context = detector._context('siteforce:loginApp2', None, None)
        self.assertEqual(context['fwuid'], 'INVALID')
        self.assertEqual(context['loaded'], {'APPLICATION@markup://siteforce:loginApp2': 'siteforce:loginApp2'})
        self.assertEqual(detector._refresh_fwuid('Expected: abc.def== Actual: INVALID', context), 'abc.def==')

    def test_encoded_resource_path_is_not_mistaken_for_fwuid(self):
        info = {'app_prefixes': [], 'custom_objects': []}
        Detector()._extract_bootstrap('<script src="/s/sfsites/l/encoded-context/resource.js"></script>', info)
        self.assertNotIn('fwuid', info)

    def test_all_upstream_endpoint_variants(self):
        for suffix in ('/s/sfsites/aura', '/s/aura', '/aura', '/sfsites/aura'):
            with self.subTest(suffix=suffix):
                endpoint = ORIGIN + suffix
                self.assertEqual(self.scan(Community(endpoint))['aura_endpoint'], endpoint)

    def test_canonical_endpoint_is_used_for_followup_requests(self):
        endpoint = ORIGIN + '/s/sfsites/aura'
        canonical = ORIGIN + '/partners/s/sfsites/aura'
        fetch = Community(endpoint, canonical=canonical)
        result = self.scan(fetch)
        self.assertEqual(result['aura_endpoint'], canonical)
        posts = [url for method, url, _ in fetch.calls if method == 'POST']
        self.assertEqual(posts[1:], [canonical, canonical])
        self.assertEqual(result['verdict'], 'leaking')

    def test_bootstrap_html_is_not_an_aura_message_endpoint(self):
        fetch = Community(ORIGIN + '/does-not-exist', bootstrap=BOOTSTRAP)
        result = self.scan(fetch)
        self.assertIsNone(result['aura_endpoint'])

    def test_gets_context_from_app_page_when_root_has_none(self):
        base = Community(ORIGIN + '/s/sfsites/aura')

        def fetch(method, url, **kwargs):
            result = base(method, url, **kwargs)
            if method == 'GET' and url == ORIGIN + '/s':
                result.body = BOOTSTRAP.encode()
            return result

        result = self.scan(fetch)
        self.assertEqual(result['app'], 'siteforce:communityApp')
        self.assertEqual(result['fwuid'], 'SERVER_FW')
        self.assertEqual(result['verdict'], 'leaking')

    def test_response_actions_are_correlated_by_id(self):
        result = self.scan(Community(ORIGIN + '/s/aura', bootstrap=BOOTSTRAP))
        self.assertEqual(result['objects_readable'], 1)

    def test_cancel_makes_no_requests(self):
        fetch = Community(ORIGIN + '/aura')
        with patch('app.salesforce._addresses_are_public'):
            Detector(fetch=fetch).run(ORIGIN, lambda: True, lambda *_: None)
        self.assertEqual(fetch.calls, [])


class RedirectTests(unittest.TestCase):
    def fetch_redirect(self, status, location='/partners/s/aura'):
        opener = MagicMock()
        response = opener.open.return_value.__enter__.return_value
        response.status = 200
        response.headers = {}
        response.url = ORIGIN + location
        response.read.return_value = b'{"actions":[]}'
        opener.open.side_effect = [_Redirect({'Location': location}, status),
                                   opener.open.return_value]
        with patch('app.salesforce._addresses_are_public') as public, \
                patch('app.salesforce.urllib.request.build_opener', return_value=opener):
            result = guarded_fetch('POST', ORIGIN + '/aura', data=b'message=test')
        return result, opener.open.call_args_list, public.call_args_list

    def test_post_body_survives_canonical_redirects(self):
        for status in (301, 302, 307, 308):
            with self.subTest(status=status):
                result, calls, checks = self.fetch_redirect(status)
                self.assertEqual(result.url, ORIGIN + '/partners/s/aura')
                self.assertEqual(calls[1].args[0].get_method(), 'POST')
                self.assertEqual(calls[1].args[0].data, b'message=test')
                self.assertEqual(len(checks), 2)

    def test_303_switches_to_get(self):
        _, calls, _ = self.fetch_redirect(303)
        self.assertEqual(calls[1].args[0].get_method(), 'GET')
        self.assertIsNone(calls[1].args[0].data)

    def test_cross_host_redirect_is_still_rejected(self):
        with self.assertRaisesRegex(ValueError, 'another host'):
            self.fetch_redirect(301, 'https://other.example.com/aura')

    def test_redirect_destination_is_revalidated(self):
        opener = MagicMock()
        opener.open.side_effect = _Redirect({'Location': '/partners/s/aura'}, 301)
        with patch('app.salesforce._addresses_are_public', side_effect=[None, ValueError('private')]), \
                patch('app.salesforce.urllib.request.build_opener', return_value=opener):
            with self.assertRaisesRegex(ValueError, 'private'):
                guarded_fetch('POST', ORIGIN + '/aura', data=b'message=test')
        self.assertEqual(opener.open.call_count, 1)
