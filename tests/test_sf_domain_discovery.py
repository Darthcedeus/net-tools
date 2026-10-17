"""Domain-only discovery tests: all HTTP and DNS are replaced with fixtures."""
import unittest
from unittest.mock import MagicMock, patch

from app.salesforce import Detector, FetchResult, guarded_fetch, _Redirect
from app.sf_discovery import DomainDiscovery, MAX_HOSTS, MAX_PAGES, MAX_REQUESTS
from test_salesforce_discovery import BOOTSTRAP, Community


ROOT = 'https://example.com'


class Site:
    def __init__(self, endpoint, pages=None):
        self.endpoint = endpoint
        self.pages = pages or {}
        self.aura = Community(endpoint)
        self.calls = []

    def __call__(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if method == 'POST' and url == self.endpoint:
            return self.aura(method, url, **kwargs)
        if method == 'GET':
            value = self.pages.get(url)
            if isinstance(value, Exception):
                raise value
            if value is not None:
                return FetchResult(200, {}, value.encode(), url)
        return FetchResult(404, {}, b'<html>Not found</html>', url)


class DomainOnlyTests(unittest.TestCase):
    def scan(self, site, target='example.com', cancel=lambda: False):
        with patch('app.salesforce._addresses_are_public'):
            return Detector(fetch=site, max_objects=1).run(target, cancel, lambda *_: None)

    def assert_endpoint(self, site, target='example.com'):
        result = self.scan(site, target)
        self.assertEqual(result['aura_endpoint'], site.endpoint)
        self.assertEqual(result['verdict'], 'leaking')
        return result

    def test_bare_domain_finds_unlinked_common_community_path(self):
        site = Site(ROOT + '/support/s/sfsites/aura')
        self.assert_endpoint(site)

    def test_robots_path_finds_custom_community(self):
        site = Site(ROOT + '/bespoke/s/aura', {ROOT + '/robots.txt': 'Disallow: /bespoke/s/\n'})
        result = self.assert_endpoint(site)
        self.assertEqual(result['discovery']['source'], 'robots.txt')

    def test_robots_sitemap_index_finds_nested_community(self):
        pages = {ROOT + '/robots.txt': 'Sitemap: /index.xml\n',
                 ROOT + '/index.xml': '<sitemapindex><sitemap><loc>/communities.xml</loc></sitemap></sitemapindex>',
                 ROOT + '/communities.xml': '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>'
                                            + ROOT + '/regional/bespoke/s/login</loc></url></urlset>'}
        self.assert_endpoint(Site(ROOT + '/regional/bespoke/s/sfsites/aura', pages))

    def test_linked_support_subdomain_is_discovered(self):
        endpoint = 'https://support.example.com/s/sfsites/aura'
        site = Site(endpoint, {ROOT: '<a href="https://support.example.com/">Support</a>'})
        result = self.assert_endpoint(site)
        self.assertEqual(result['discovery']['hosts_checked'], 2)

    def test_linked_salesforce_host_is_discovered(self):
        endpoint = 'https://acme.my.site.com/custom/s/aura'
        self.assert_endpoint(Site(endpoint, {ROOT: '<a href="https://acme.my.site.com/custom/s/">Portal</a>'}))

    def test_linked_host_also_gets_common_path_fallbacks(self):
        endpoint = 'https://support.example.com/partners/s/aura'
        self.assert_endpoint(Site(endpoint, {ROOT: '<a href="https://support.example.com/">Support</a>'}))

    def test_bootstrap_script_literal_url_is_discovered(self):
        site = Site(ROOT + '/bespoke/s/aura', {ROOT: '<script src="/app.js"></script>',
                                              ROOT + '/app.js': 'window.location.href = "/bespoke/s/login";'})
        self.assert_endpoint(site)

    def test_escaped_salesforce_bootstrap_url_is_discovered(self):
        endpoint = 'https://acme.my.site.com/s/aura'
        site = Site(endpoint, {ROOT: '<script>var portal="https:\\/\\/acme.my.site.com\\/s\\/";</script>'})
        self.assert_endpoint(site)

    def test_meta_refresh_is_discovered_without_executing_javascript(self):
        site = Site(ROOT + '/bespoke/s/aura', {ROOT: '<meta http-equiv="refresh" content="0; URL=/bespoke/s/">'})
        self.assert_endpoint(site)

    def test_nuclei_fact_endpoint_variant_is_checked(self):
        self.assert_endpoint(Site(ROOT + '/s/fact'))

    def test_unrelated_hosts_credentials_ips_and_action_links_are_ignored(self):
        links = ['https://other.test/portal', 'https://example.com.evil.test/support',
                 'https://acme.force.com.evil.test/s/', 'http://127.0.0.1/s/',
                 'http://169.254.169.254/s/', 'https://user:pass@support.example.com/s/',
                 'https://support.example.com:4444/s/', '/support/logout', 'javascript:alert(1)']
        site = Site(ROOT + '/never/s/aura', {ROOT: ''.join('<a href="' + url + '">Link</a>' for url in links)})
        result = self.scan(site)
        self.assertIsNone(result['aura_endpoint'])
        requested = {url for _, url, _ in site.calls}
        self.assertFalse(any(url in requested for url in links))
        self.assertTrue(all(url.startswith(ROOT + '/') or url == ROOT for url in requested))

    def test_bad_optional_candidate_does_not_abort_scan(self):
        pages = {ROOT: '<a href="https://private.example.com/s/">Support</a>',
                 'https://private.example.com/s/': ValueError('private destination')}
        self.assert_endpoint(Site(ROOT + '/support/s/aura', pages))

    def test_request_and_page_limits_are_enforced(self):
        pages = {ROOT: ''.join(f'<a href="/portal{i}/s/">Portal</a>' for i in range(200))}
        site = Site(ROOT + '/never/s/aura', pages)
        result = self.scan(site)
        self.assertLessEqual(len(site.calls), MAX_REQUESTS)
        self.assertLessEqual(result['discovery']['pages_checked'], MAX_PAGES)
        self.assertTrue(result['discovery']['limited'])
        self.assertTrue(all(kwargs['timeout'] <= 3 for _, _, kwargs in site.calls))

    def test_host_limit_is_enforced(self):
        pages = {ROOT: ''.join(f'<a href="https://support{i}.example.com/s/">Portal</a>' for i in range(20))}
        site = Site(ROOT + '/never/s/aura', pages)
        result = self.scan(site)
        hosts = {url.split('/')[2] for _, url, _ in site.calls}
        self.assertLessEqual(len(hosts), MAX_HOSTS)
        self.assertLessEqual(result['discovery']['hosts_checked'], MAX_HOSTS)

    def test_cancel_stops_discovery_without_http(self):
        site = Site(ROOT + '/s/aura')
        self.scan(site, cancel=lambda: True)
        self.assertEqual(site.calls, [])

    def test_deadline_stops_new_requests(self):
        fetch = MagicMock()
        now = [0]
        discovery = DomainDiscovery(ROOT, fetch, lambda: False, (ValueError,), clock=lambda: now[0])
        now[0] = 46
        self.assertEqual(list(discovery.pages()), [])
        fetch.assert_not_called()
        self.assertTrue(discovery.limited)

    def test_xml_entities_are_not_expanded(self):
        xml = '<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///etc/passwd">]><urlset><url><loc>&secret;</loc></url></urlset>'
        site = Site(ROOT + '/never/s/aura', {ROOT + '/sitemap.xml': xml})
        self.assertIsNone(self.scan(site)['aura_endpoint'])

    def test_sitemap_index_nesting_is_bounded(self):
        pages = {ROOT + '/sitemap.xml': '<sitemapindex><sitemap><loc>/i0.xml</loc></sitemap></sitemapindex>'}
        for i in range(10):
            pages[ROOT + f'/i{i}.xml'] = f'<sitemapindex><sitemap><loc>/i{i + 1}.xml</loc></sitemap></sitemapindex>'
        site = Site(ROOT + '/never/s/aura', pages)
        self.assertTrue(self.scan(site)['discovery']['limited'])
        requested = {url for _, url, _ in site.calls}
        self.assertIn(ROOT + '/i2.xml', requested)
        self.assertNotIn(ROOT + '/i3.xml', requested)


class ScopedRedirectTests(unittest.TestCase):
    def test_default_detector_follows_canonical_domain_and_linked_tenant(self):
        endpoint = 'https://tenant.my.site.com/s/aura'
        site = Site(endpoint, {'https://www.example.com/': '<a href="https://tenant.my.site.com/s/">Support</a>',
                               'https://tenant.my.site.com/s/': BOOTSTRAP})
        opener = MagicMock()

        def open_request(request, timeout):
            if request.full_url == ROOT:
                raise _Redirect({'Location': 'https://www.example.com/'}, 301)
            result = site(request.get_method(), request.full_url, data=request.data, timeout=timeout)
            response = MagicMock()
            response.__enter__.return_value = response
            response.status, response.headers, response.url = result.status, result.headers, result.url
            response.read.return_value = result.body
            return response

        opener.open.side_effect = open_request
        with patch('app.salesforce._addresses_are_public'), \
                patch('app.salesforce.urllib.request.build_opener', return_value=opener):
            result = Detector(max_objects=1).run('example.com', lambda: False, lambda *_: None)
        self.assertEqual(result['aura_endpoint'], endpoint)
        self.assertEqual(result['verdict'], 'leaking')
        self.assertEqual(result['discovery']['hosts_checked'], 3)

    def test_www_redirect_is_allowed_and_public_address_check_is_repeated(self):
        discovery = DomainDiscovery(ROOT, None, lambda: False, (ValueError,))
        opener = MagicMock()
        response = opener.open.return_value.__enter__.return_value
        response.status, response.headers, response.url = 200, {}, 'https://www.example.com/'
        response.read.return_value = b'<html>Home</html>'
        opener.open.side_effect = [_Redirect({'Location': response.url}, 301), opener.open.return_value]
        with patch('app.salesforce._addresses_are_public') as public, \
                patch('app.salesforce.urllib.request.build_opener', return_value=opener):
            result = guarded_fetch('GET', ROOT, redirect_policy=discovery.allow_redirect)
        self.assertEqual(result.url, response.url)
        self.assertEqual(public.call_count, 2)

    def test_scoped_redirect_still_rejects_private_destination(self):
        discovery = DomainDiscovery(ROOT, None, lambda: False, (ValueError,))
        opener = MagicMock()
        opener.open.side_effect = _Redirect({'Location': 'https://private.example.com/s/'}, 301)
        with patch('app.salesforce._addresses_are_public', side_effect=[None, ValueError('private')]), \
                patch('app.salesforce.urllib.request.build_opener', return_value=opener):
            with self.assertRaisesRegex(ValueError, 'private'):
                guarded_fetch('GET', ROOT, redirect_policy=discovery.allow_redirect)
        self.assertEqual(opener.open.call_count, 1)

    def test_external_and_credential_redirects_are_rejected(self):
        discovery = DomainDiscovery(ROOT, None, lambda: False, (ValueError,))
        for url in ['https://other.test/s/', 'https://user:pass@example.com/s/']:
            opener = MagicMock()
            opener.open.side_effect = _Redirect({'Location': url}, 301)
            with self.subTest(url=url), patch('app.salesforce._addresses_are_public'), \
                    patch('app.salesforce.urllib.request.build_opener', return_value=opener):
                with self.assertRaisesRegex(ValueError, 'out-of-scope'):
                    guarded_fetch('GET', ROOT, redirect_policy=discovery.allow_redirect)
