"""Read-only Salesforce Aura/Lightning (Experience Cloud) exposure detector.

The detector fingerprints whether a target runs the Salesforce Aura framework
and, if so, probes the unauthenticated Aura endpoint as a guest to see which
standard and custom objects are readable. For each readable object it records
the total record count and a small, truncated sample of records as evidence.

It is deliberately a *detector*, not a data-exfiltration tool: it enumerates
objects and keeps a bounded handful of sample rows, never the full dataset.
All outbound requests go through a guarded fetcher that re-resolves the target
host and refuses private, loopback, link-local, and reserved addresses so an
internet-exposed instance cannot be aimed at internal services. Every request
is bounded in size and the whole scan is bounded in time by the job runner.
Network access is injectable so the logic can be unit tested without a server.
"""
import ipaddress
import json
import re
import socket
import urllib.error
import urllib.request
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

# Paths that commonly expose the Aura message endpoint, relative to the site
# root or to a discovered application prefix such as /partners or /support.
AURA_PATHS = ('/aura', '/s/sfsites/aura', '/sfsites/aura')

# Strings that identify a Salesforce Aura/Lightning (Experience Cloud) site in
# the landing page markup or inline bootstrap script.
HTML_MARKERS = ('siteforce:communityApp', '/auraFW/', 'aura_prod', 'auraConfig',
                'window.Aura', 'resource/aura', 'appBootstrap')

# Strings that confirm a live Aura message endpoint in a response body, even
# when the request is rejected. Salesforce echoes these framework events.
AURA_RESPONSE_MARKERS = ('aura:invalidSession', 'aura:clientOutOfSync', 'markup://',
                         '"exceptionEvent"', 'AuraEnabled', 'clientOutOfSync',
                         'ClientSideEventException')

DEFAULT_APP = 'siteforce:communityApp'
MAX_BYTES = 2_000_000
MAX_REDIRECTS = 4
SAMPLE_FIELD_LIMIT = 24
SAMPLE_VALUE_LIMIT = 200

# Guest users of a misconfigured community most often leak these standard
# objects. Custom objects discovered from the site are probed in addition.
DEFAULT_OBJECTS = (
    'User', 'Account', 'Contact', 'Case', 'Lead', 'Opportunity', 'Document',
    'ContentDocument', 'ContentVersion', 'Attachment', 'CaseComment', 'Note',
    'Campaign', 'CampaignMember', 'Task', 'Event', 'Group', 'Product2',
)

GET_CONFIG_DESCRIPTOR = ('serviceComponent://ui.force.components.controllers.'
                         'hostConfig.HostConfigController/ACTION$getConfigData')
GET_ITEMS_DESCRIPTOR = ('serviceComponent://ui.force.components.controllers.lists.'
                        'selectableListDataProvider.SelectableListDataProviderController/'
                        'ACTION$getItems')


class DetectorError(Exception):
    """A target-level failure that should fail the scan with a safe message."""


class FetchResult:
    __slots__ = ('status', 'headers', 'body', 'url')

    def __init__(self, status, headers, body, url):
        self.status = status
        self.headers = headers
        self.body = body
        self.url = url

    def text(self):
        try:
            return self.body.decode('utf-8', 'replace')
        except Exception:
            return ''


def _addresses_are_public(host, port):
    """Resolve a host and require every address to be a public unicast IP."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError('The target host could not be resolved.') from None
    if not infos:
        raise ValueError('The target host could not be resolved.')
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            raise ValueError('The target resolved to an invalid address.') from None
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified or
                getattr(ip, 'is_site_local', False)):
            raise ValueError('The target resolves to a private or reserved address.')


def safe_target(url):
    """Validate and normalize a user-supplied target URL.

    Returns the normalized ``scheme://host[:port]`` origin. Raises ValueError
    for anything that is not a public http(s) host, which blocks attempts to
    scan loopback, private, link-local, and cloud-metadata addresses.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError('Enter a target URL, such as https://example.com.')
    candidate = url.strip()
    if '://' not in candidate:
        candidate = 'https://' + candidate
    parsed = urlsplit(candidate)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError('The target must be an http:// or https:// URL.')
    if parsed.username or parsed.password:
        raise ValueError('Remove credentials from the target URL.')
    host = parsed.hostname
    if not host or len(candidate) > 2000:
        raise ValueError('Enter a valid target URL.')
    try:
        ipaddress.ip_address(host)
        raise ValueError('Enter a hostname rather than an IP address.')
    except ValueError as error:
        if 'hostname rather' in str(error):
            raise
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    if not 0 < port <= 65535:
        raise ValueError('Enter a valid target port.')
    _addresses_are_public(host, port)
    netloc = host if parsed.port is None else f'{host}:{parsed.port}'
    return urlunsplit((parsed.scheme, netloc, '', '', ''))


def guarded_fetch(method, url, headers=None, data=None, timeout=10, max_bytes=MAX_BYTES):
    """Fetch a URL, re-validating the host and refusing cross-host redirects.

    The host is re-resolved on every hop and rejected if it points at a private
    or reserved address, so DNS rebinding between requests cannot redirect the
    scanner at internal infrastructure. Error responses are returned rather than
    raised, because a live Aura endpoint signals itself through 4xx/5xx bodies.
    """
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        parsed = urlsplit(current)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            raise ValueError('Refusing to follow a non-HTTP target.')
        _addresses_are_public(parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))
        request = urllib.request.Request(current, data=data, method=method,
                                         headers=headers or {})
        try:
            opener = urllib.request.build_opener(_NoRedirect)
            with opener.open(request, timeout=timeout) as response:
                body = response.read(max_bytes + 1)[:max_bytes]
                return FetchResult(response.status, dict(response.headers), body, response.url)
        except _Redirect as redirect:
            location = redirect.headers.get('Location')
            if not location:
                raise ValueError('The target returned an invalid redirect.') from None
            following = urlsplit(urljoin(current, location))
            if (following.hostname or '').lower() != (parsed.hostname or '').lower():
                raise ValueError('Refusing to follow a redirect to another host.') from None
            current = urlunsplit(following)
            data = None
            method = 'GET'
            continue
        except urllib.error.HTTPError as error:
            body = error.read(max_bytes + 1)[:max_bytes] if error.fp else b''
            return FetchResult(error.code, dict(error.headers or {}), body, current)
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as error:
            raise DetectorError(f'The target could not be reached: {type(error).__name__}.') from None
    raise ValueError('The target redirected too many times.')


class _Redirect(Exception):
    def __init__(self, headers):
        self.headers = headers


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise _Redirect(headers)


class Detector:
    """Fingerprints a target and enumerates guest-readable Salesforce objects."""

    def __init__(self, fetch=None, sample_size=10, max_objects=50, request_timeout=10):
        self.fetch = fetch or guarded_fetch
        self.sample_size = max(1, min(int(sample_size), 25))
        self.max_objects = max(1, min(int(max_objects), 200))
        self.request_timeout = request_timeout

    # -- public entry point -------------------------------------------------

    def run(self, target, cancel, emit):
        """Scan one target.

        ``cancel`` is a callable returning True when the scan should stop.
        ``emit`` is called as ``emit(kind, payload)`` with kind in
        {"meta", "finding"}. Returns a summary dict with the final verdict.
        """
        origin = safe_target(target)
        summary = {'is_salesforce': False, 'aura_endpoint': None, 'verdict': 'not_salesforce',
                   'app': None, 'fwuid': None, 'self_registration': False,
                   'objects_checked': 0, 'objects_readable': 0}

        landing = self._fingerprint(origin, cancel)
        summary.update(landing)
        emit('meta', dict(summary))
        if cancel():
            return summary

        endpoint, context = self._locate_endpoint(origin, landing, cancel)
        if not endpoint:
            return summary
        summary['is_salesforce'] = True
        summary['aura_endpoint'] = endpoint
        summary['app'] = context.get('app')
        summary['fwuid'] = context.get('fwuid')
        summary['verdict'] = 'salesforce'
        emit('meta', dict(summary))

        objects = self._object_list(endpoint, context, landing, cancel)
        checked = 0
        readable = 0
        for name, prefix in objects:
            if cancel() or checked >= self.max_objects:
                break
            checked += 1
            finding = self._probe_object(endpoint, context, name, prefix, cancel)
            if finding is None:
                continue
            if finding['readable']:
                readable += 1
            emit('finding', finding)
        summary['objects_checked'] = checked
        summary['objects_readable'] = readable
        if readable:
            summary['verdict'] = 'leaking'
        emit('meta', dict(summary))
        return summary

    # -- fingerprint --------------------------------------------------------

    def _fingerprint(self, origin, cancel):
        info = {'app': None, 'fwuid': None, 'app_id': None, 'self_registration': False,
                'app_prefixes': [], 'custom_objects': []}
        try:
            result = self.fetch('GET', origin + '/', timeout=self.request_timeout)
        except DetectorError:
            return info
        body = result.text()
        info['fingerprint'] = any(marker in body for marker in HTML_MARKERS)
        self._extract_bootstrap(body, info)
        info['self_registration'] = 'SelfRegister' in body or 'self_register' in body
        return info

    def _extract_bootstrap(self, body, info):
        fwuid = re.search(r'"fwuid"\s*:\s*"([^"]{4,120})"', body) or \
            re.search(r'/auraFW/javascript/([^/"\\]{4,120})/', body) or \
            re.search(r'/l/([^/"\\]{4,120})/', body)
        if fwuid:
            info['fwuid'] = fwuid.group(1)
        app = re.search(r'"app"\s*:\s*"([^"]{3,120})"', body) or \
            re.search(r'(APPLICATION@markup://[\w:.-]+)', body)
        if app:
            value = app.group(1)
            info['app'] = value.split('://', 1)[-1] if '@markup' in value else value
        loaded = re.search(r'"(APPLICATION@markup://[^"]+)"\s*:\s*"([^"]+)"', body)
        if loaded:
            info['app'] = info['app'] or loaded.group(1).split('://', 1)[-1]
            info['app_id'] = loaded.group(2)
        for match in re.findall(r'/([A-Za-z0-9_]+)/s(?:/|")', body):
            prefix = '/' + match
            if prefix not in info['app_prefixes'] and match not in ('sfsites', 'auraFW'):
                info['app_prefixes'].append(prefix)
        for match in set(re.findall(r'"apiName"\s*:\s*"([A-Za-z0-9_]+__c)"', body)):
            if match not in info['custom_objects']:
                info['custom_objects'].append(match)

    # -- Aura endpoint ------------------------------------------------------

    def _locate_endpoint(self, origin, landing, cancel):
        app = landing.get('app') or DEFAULT_APP
        fwuid = landing.get('fwuid')
        context = self._context(app, fwuid, landing.get('app_id'))
        prefixes = [''] + landing.get('app_prefixes', [])
        for prefix in prefixes:
            for path in AURA_PATHS:
                if cancel():
                    return None, context
                endpoint = origin + prefix + path
                probe = self._call(endpoint, context, [self._config_action()], cancel)
                if probe is None:
                    continue
                text = probe.text()
                if not self._looks_like_aura(text):
                    continue
                refreshed = self._refresh_fwuid(text, context)
                if refreshed and refreshed != context['fwuid']:
                    context['fwuid'] = refreshed
                return endpoint, context
        return None, context

    def _looks_like_aura(self, text):
        """A live Aura endpoint echoes framework markers or a message envelope."""
        if any(marker in text for marker in AURA_RESPONSE_MARKERS):
            return True
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return False
        return isinstance(data, dict) and (isinstance(data.get('actions'), list)
                                           or 'context' in data or 'perfSummary' in data)

    def _refresh_fwuid(self, text, context):
        match = re.search(r'"newFwuid"\s*:\s*"([^"]+)"', text) or \
            re.search(r'Expected:\s*([\w-]+)\s+Actual', text) or \
            re.search(r'"fwuid"\s*:\s*"([^"]+)"', text)
        return match.group(1) if match else None

    def _context(self, app, fwuid, app_id):
        loaded = {}
        if app_id:
            loaded[f'APPLICATION@markup://{app}'] = app_id
        return {'mode': 'PROD', 'fwuid': fwuid or '', 'app': app,
                'loaded': loaded, 'dn': [], 'globals': {}, 'uad': False}

    # -- object enumeration -------------------------------------------------

    def _object_list(self, endpoint, context, landing, cancel):
        """Return (name, key_prefix) pairs to probe, best-effort from the site."""
        discovered = {}
        result = self._call(endpoint, context, [self._config_action()], cancel)
        if result is not None:
            value = self._action_value(result.text(), 'getConfigData')
            mapping = (value or {}).get('apiNamesToKeyPrefixes') if isinstance(value, dict) else None
            if isinstance(mapping, dict):
                for name, prefix in mapping.items():
                    if isinstance(name, str):
                        discovered[name] = prefix if isinstance(prefix, str) else None
        for name in DEFAULT_OBJECTS:
            discovered.setdefault(name, None)
        for name in landing.get('custom_objects', []):
            discovered.setdefault(name, None)
        return list(discovered.items())

    def _probe_object(self, endpoint, context, name, prefix, cancel):
        result = self._call(endpoint, context, [self._items_action(name)], cancel)
        if result is None:
            return None
        action = self._action(result.text(), 'getItems')
        if action is None:
            return None
        finding = {'object': name, 'key_prefix': prefix, 'readable': False,
                   'record_count': None, 'samples': []}
        if action.get('state') != 'SUCCESS':
            return finding
        value = action.get('returnValue') or {}
        records = self._records(value)
        count = value.get('totalCount')
        if not isinstance(count, int) or count < 0:
            count = len(records) if records else None
        finding['record_count'] = count
        finding['readable'] = bool(records) or (isinstance(count, int) and count > 0)
        finding['samples'] = [self._sample(record) for record in records[:self.sample_size]]
        return finding

    @staticmethod
    def _records(value):
        for key in ('result', 'records', 'items', 'data'):
            candidate = value.get(key) if isinstance(value, dict) else None
            if isinstance(candidate, list):
                return candidate
        return []

    def _sample(self, record):
        """Flatten and truncate one record so stored evidence stays small."""
        flat = {}
        source = record.get('record', record) if isinstance(record, dict) else {}
        fields = source.get('fields', source) if isinstance(source, dict) else {}
        if isinstance(fields, dict):
            for key, raw in list(fields.items())[:SAMPLE_FIELD_LIMIT]:
                value = raw.get('value') if isinstance(raw, dict) and 'value' in raw else raw
                if isinstance(value, (dict, list)):
                    value = json.dumps(value)[:SAMPLE_VALUE_LIMIT]
                elif value is not None:
                    value = str(value)[:SAMPLE_VALUE_LIMIT]
                flat[str(key)[:64]] = value
        return flat

    # -- Aura message plumbing ---------------------------------------------

    def _config_action(self):
        return {'id': '1;a', 'descriptor': GET_CONFIG_DESCRIPTOR,
                'callingDescriptor': 'UNKNOWN', 'params': {}}

    def _items_action(self, name):
        return {'id': '2;a', 'descriptor': GET_ITEMS_DESCRIPTOR,
                'callingDescriptor': 'UNKNOWN',
                'params': {'entityNameOrId': name, 'layoutType': 'FULL',
                           'pageSize': self.sample_size, 'currentPage': 0,
                           'getCount': True, 'enableRowActions': False,
                           'useTimeout': False}}

    def _call(self, endpoint, context, actions, cancel):
        if cancel():
            return None
        payload = urlencode({'message': json.dumps({'actions': actions}),
                             'aura.context': json.dumps(context),
                             'aura.pageURI': '/', 'aura.token': 'undefined'}).encode()
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'X-SFDC-Aura-Mode': 'PROD', 'Accept': 'application/json',
                   'User-Agent': 'NetTools-SalesforceDetector/1.0'}
        try:
            return self.fetch('POST', endpoint, headers=headers, data=payload,
                              timeout=self.request_timeout)
        except DetectorError:
            return None

    def _action(self, text, needle):
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return None
        for action in data.get('actions', []) if isinstance(data, dict) else []:
            if isinstance(action, dict) and needle in str(action.get('descriptor', '')):
                return action
        return None

    def _action_value(self, text, needle):
        action = self._action(text, needle)
        if action and action.get('state') == 'SUCCESS':
            return action.get('returnValue')
        return None
