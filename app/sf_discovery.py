"""Bounded discovery of public Salesforce community URLs from a domain.

This reads links, bootstrap scripts, robots.txt and sitemaps. It neither runs
JavaScript nor guesses Salesforce tenant names. Linked subdomains and linked
Salesforce-hosted sites can be visited; unrelated external hosts cannot.
The caller supplies the guarded HTTP fetcher and its handled error types.
"""
import heapq
import html
import ipaddress
import re
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit
from xml.etree import ElementTree


MAX_REQUESTS = 64
MAX_PAGES = 16
MAX_SCRIPTS = 3
MAX_HOSTS = 4
MAX_QUEUE = 64
MAX_LINKS = 200
MAX_BYTES = 256_000
MAX_SECONDS = 45
COMMON_PATHS = ('/s/', '/support/s/', '/community/s/', '/partners/s/',
                '/customers/s/', '/portal/s/', '/help/s/')
SALESFORCE_SUFFIXES = ('.my.site.com', '.force.com', '.salesforce-sites.com')
SITE_HINT = re.compile(r'(?:/s(?:/|$)|aura|sfsites|community|communities|support|partner|customer|portal|help|login)', re.I)


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attrs):
        if len(self.links) >= MAX_LINKS:
            return
        attrs = dict(attrs)
        if tag in ('a', 'link') and attrs.get('href'):
            self.links.append((attrs['href'], 'page'))
        elif tag in ('script', 'iframe') and attrs.get('src'):
            self.links.append((attrs['src'], 'script' if tag == 'script' else 'page'))
        elif tag == 'meta' and attrs.get('http-equiv', '').lower() == 'refresh':
            match = re.search(r'url\s*=\s*[\"\']?([^\"\']+)', attrs.get('content', ''), re.I)
            if match:
                self.links.append((match.group(1).strip(), 'page'))


class DomainDiscovery:
    def __init__(self, target, fetch, cancel, errors, clock=None):
        self.target = target
        self.fetch = fetch
        self.cancel = cancel
        self.errors = errors
        self.clock = clock or time.monotonic
        self.deadline = self.clock() + MAX_SECONDS
        parsed = urlsplit(target)
        self.host = parsed.hostname.lower().rstrip('.')
        self.domain = self.host[4:] if self.host.startswith('www.') else self.host
        self.port = parsed.port
        self.origin = urlunsplit((parsed.scheme, parsed.netloc, '', '', ''))
        self.requests = 0
        self.pages_checked = 0
        self.scripts_checked = 0
        self.limited = False
        self.hosts = {self.host}
        self.queue = []
        self.queued = set()
        self.visited = set()
        self.sources = {}
        self.seeded = set()

    def in_scope(self, url):
        """Validate every discovered URL, including redirect destinations."""
        try:
            parsed = urlsplit(url)
            host = (parsed.hostname or '').lower().rstrip('.')
            if (parsed.scheme not in ('http', 'https') or not host or
                    parsed.username is not None or parsed.password is not None or
                    len(url) > 2000 or parsed.port not in (None, 80, 443, self.port)):
                return False
            try:
                ipaddress.ip_address(host)
                return False
            except ValueError:
                pass
            return (host == self.domain or host.endswith('.' + self.domain) or
                    any(host.endswith(suffix) for suffix in SALESFORCE_SUFFIXES))
        except ValueError:
            return False

    def stopped(self):
        if self.cancel():
            return True
        if self.requests >= MAX_REQUESTS or self.clock() >= self.deadline:
            self.limited = True
            return True
        return False

    def allow_redirect(self, url):
        if self.stopped() or not self.in_scope(url):
            return False
        host = urlsplit(url).hostname.lower().rstrip('.')
        if host not in self.hosts and len(self.hosts) >= MAX_HOSTS:
            self.limited = True
            return False
        self.hosts.add(host)
        return True

    def request(self, method, url, **kwargs):
        if self.stopped() or not self.in_scope(url):
            return None
        host = urlsplit(url).hostname.lower().rstrip('.')
        if host not in self.hosts:
            if len(self.hosts) >= MAX_HOSTS:
                self.limited = True
                return None
            self.hosts.add(host)
        self.requests += 1
        kwargs['timeout'] = min(kwargs.get('timeout', 3), 3, max(0.1, self.deadline - self.clock()))
        kwargs['max_bytes'] = min(kwargs.get('max_bytes', MAX_BYTES), 2_000_000)
        try:
            return self.fetch(method, url, **kwargs)
        except self.errors:
            # An inaccessible optional candidate must not fail the target job.
            return None

    def _enqueue(self, value, base, kind='page', priority=2, source='link', depth=0):
        value = html.unescape(value).replace('\\/', '/').replace('\\u002f', '/').replace('\\u002F', '/')
        value = value.replace('\\u003a', ':').replace('\\u003A', ':')
        try:
            parsed = urlsplit(urljoin(base, value.strip()))
            # Drop tracking queries/fragments, and never follow action links.
            if re.search(r'(?:logout|signout|delete|unsubscribe)', parsed.path, re.I):
                return
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or '/', '', ''))
        except ValueError:
            return
        if not self.in_scope(url) or url in self.queued or url in self.visited:
            return
        if kind == 'script' and parsed.hostname != urlsplit(base).hostname:
            return
        if len(self.queue) >= MAX_QUEUE:
            self.limited = True
            return
        if kind == 'page':
            if not SITE_HINT.search(parsed.path) and parsed.hostname == urlsplit(base).hostname:
                return
            # Query the app root rather than individual records or login pages.
            match = re.search(r'/s(?:/|$)', parsed.path)
            if match:
                url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path[:match.start()] + '/s/', '', ''))
        if url in self.queued or url in self.visited:
            return
        self.queued.add(url)
        self.sources[url] = source
        heapq.heappush(self.queue, (priority, len(self.sources), url, kind, depth))

    def _extract(self, body, base, kind, depth):
        if kind == 'robots':
            for name, value in re.findall(r'(?im)^\s*(sitemap|allow|disallow)\s*:\s*([^\s#]+)', body)[:MAX_LINKS]:
                if name.lower() == 'sitemap':
                    self._enqueue(value, base, 'sitemap', 0, 'robots.txt', depth)
                elif '*' not in value and SITE_HINT.search(value):
                    self._enqueue(value, base, source='robots.txt', priority=1, depth=depth)
            return
        if kind == 'sitemap':
            if depth > 2:
                self.limited = True
                return
            if '<!DOCTYPE' in body.upper():
                return
            try:
                root = ElementTree.fromstring(body)
            except ElementTree.ParseError:
                return
            index = root.tag.rsplit('}', 1)[-1] == 'sitemapindex'
            for node in list(root.iter())[:MAX_LINKS * 4]:
                if node.tag.rsplit('}', 1)[-1] == 'loc' and node.text:
                    self._enqueue(node.text, base, 'sitemap' if index else 'page',
                                  0 if index else 1, 'sitemap', depth + 1 if index else 0)
            return
        if depth >= 2:
            return
        if kind == 'page':
            parser = _Links()
            parser.feed(body)
            for value, link_kind in parser.links:
                self._enqueue(value, base, link_kind, 1 if link_kind == 'page' else 2,
                              'HTML link' if link_kind == 'page' else 'bootstrap script', depth + 1)
        # Literal bootstrap URLs and JavaScript redirects are inspected without
        # executing scripts. Only relevant page URLs pass the enqueue filter.
        for value in re.findall(r'[\"\']((?:https?:)?(?:\\?/){1,2}[^\"\'<>\s]{1,1800})[\"\']', body)[:MAX_LINKS]:
            self._enqueue(value, base, source='bootstrap URL', priority=1, depth=depth + 1)

    def _seed(self, origin):
        if origin in self.seeded:
            return
        self.seeded.add(origin)
        for path, kind in (('/robots.txt', 'robots'), ('/sitemap.xml', 'sitemap'), ('/s/sitemap.xml', 'sitemap')):
            self._enqueue(path, origin, kind, 0, kind)
        for path in COMMON_PATHS:
            # A linked portal host is stronger evidence than guessed paths on
            # a corporate homepage. Try its fallbacks before the root guesses.
            self._enqueue(path, origin, priority=2 if origin != self.origin else 3,
                          source='common community path')

    def pages(self):
        """Yield candidate page responses, expanding bounded discovery hints."""
        self.sources[self.target] = 'supplied domain'
        heapq.heappush(self.queue, (-1, 0, self.target, 'page', 0))
        self.queued.add(self.target)
        self._seed(self.origin)
        while self.queue and not self.stopped():
            _, _, url, kind, depth = heapq.heappop(self.queue)
            if url in self.visited:
                continue
            self.visited.add(url)
            if kind == 'script':
                if self.scripts_checked >= MAX_SCRIPTS:
                    self.limited = True
                    continue
                self.scripts_checked += 1
            if kind == 'page':
                if self.pages_checked >= MAX_PAGES:
                    self.limited = True
                    continue
                self.pages_checked += 1
            result = self.request('GET', url)
            if result is not None:
                parsed = urlsplit(result.url)
                self._seed(urlunsplit((parsed.scheme, parsed.netloc, '', '', '')))
                self._extract(result.text(), result.url, kind, depth)
            if kind == 'page':
                yield url, result

    def details(self):
        return {'requests': self.requests, 'pages_checked': self.pages_checked,
                'hosts_checked': len(self.hosts), 'limited': self.limited}
