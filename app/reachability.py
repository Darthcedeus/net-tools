"""Bounded HTTP/HTTPS reachability probing for discovered hosts.

Discovery proves a host exists in DNS; it does not prove anything is listening.
This module performs a single, bounded GET against ``https://`` and ``http://``
for each host and records whether it answered, with what status, where it
redirected, and which server banner it returned. Redirects are *not* followed:
any HTTP response — including 3xx/4xx/5xx — proves the host served HTTP, while a
connection failure, timeout, or TLS error means it did not (and is recorded as
such). This keeps the probe cheap and avoids chasing redirects to other hosts.

Every request reuses the Salesforce detector's public-address guard, so a probe
can never be aimed at loopback, private, link-local, or reserved addresses.
Network access is injectable so the logic can be unit tested without a server.
"""
import socket
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from app.salesforce import _addresses_are_public, _NoRedirect, _Redirect

USER_AGENT = 'NetTools-Reachability/1.0'
MAX_BYTES = 2048
SCHEMES = ('https', 'http')


def _classify_error(error):
    if isinstance(error, (ssl.SSLCertVerificationError,)):
        return 'tls_cert_error'
    if isinstance(error, ssl.SSLError):
        return 'tls_error'
    if isinstance(error, socket.timeout):
        return 'timeout'
    reason = getattr(error, 'reason', error)
    if isinstance(reason, socket.timeout):
        return 'timeout'
    if isinstance(reason, (ConnectionRefusedError,)):
        return 'refused'
    if isinstance(reason, ssl.SSLError):
        return 'tls_cert_error' if isinstance(reason, ssl.SSLCertVerificationError) else 'tls_error'
    if isinstance(reason, socket.gaierror):
        return 'dns_error'
    return 'unreachable'


def _probe_scheme(scheme, host, timeout):
    """Probe one scheme for one host. Returns a JSON-serializable result dict.

    ``ok`` is True whenever the host returned any HTTP response (the host is
    serving), regardless of the status code. Connection, timeout, and TLS
    failures set ``ok`` to False with a classified ``error``.
    """
    port = 443 if scheme == 'https' else 80
    try:
        _addresses_are_public(host, port)
    except ValueError:
        return {'ok': False, 'error': 'dns_error'}
    url = f'{scheme}://{host}/'
    request = urllib.request.Request(
        url, method='GET',
        headers={'User-Agent': USER_AGENT, 'Accept': '*/*', 'Connection': 'close'})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            response.read(MAX_BYTES)
            server = response.headers.get('Server')
            return {'ok': True, 'status': response.status, 'server': server,
                    'final_url': response.url, 'location': None}
    except _Redirect as redirect:
        # A redirect response still proves the host served HTTP; record where it
        # points without following it.
        return {'ok': True, 'status': redirect.code, 'server': redirect.headers.get('Server'),
                'final_url': url, 'location': redirect.headers.get('Location')}
    except urllib.error.HTTPError as error:
        headers = error.headers or {}
        return {'ok': True, 'status': error.code, 'server': headers.get('Server'),
                'final_url': url, 'location': headers.get('Location')}
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, ConnectionError, OSError) as error:
        return {'ok': False, 'error': _classify_error(error)}


def probe_host(host, timeout=8, probe=None):
    """Probe a host over HTTPS then HTTP and summarize reachability.

    ``probe`` is the per-scheme prober (injectable for tests); it defaults to a
    real guarded network probe. The summary records which scheme served the
    host, the status it returned, and the full per-scheme detail.
    """
    probe = probe or (lambda scheme, h: _probe_scheme(scheme, h, timeout))
    started = time.monotonic()
    details = {scheme: probe(scheme, host) for scheme in SCHEMES}
    elapsed_ms = int((time.monotonic() - started) * 1000)
    served = next((scheme for scheme in SCHEMES if details[scheme].get('ok')), None)
    chosen = details.get(served) if served else None
    return {
        'host': host,
        'reachable': served is not None,
        'scheme': served,
        'status': chosen.get('status') if chosen else None,
        'server': (chosen.get('server') if chosen else None) or None,
        'final_url': chosen.get('final_url') if chosen else None,
        'error': None if served else (details['https'].get('error') or details['http'].get('error')),
        'elapsed_ms': elapsed_ms,
        'details': details,
    }
