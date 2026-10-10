"""Small, dependency-free password and domain helpers."""
import hashlib
import hmac
import ipaddress
import re
import secrets


def hash_password(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 600_000).hex()
    return f'pbkdf2_sha256$600000${salt}${digest}'


def verify_password(password, encoded):
    try:
        algorithm, iterations, salt, expected = encoded.split('$')
        if algorithm != 'pbkdf2_sha256' or not 100_000 <= int(iterations) <= 1_000_000:
            return False
        actual = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), int(iterations)).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def normalize_domain(value):
    if not isinstance(value, str) or len(value) > 253:
        raise ValueError('Enter a domain, such as example.com, without a URL or path.')
    try:
        domain = value.strip().rstrip('.').encode('idna').decode('ascii').lower()
    except UnicodeError:
        raise ValueError('This domain is not valid.') from None
    labels = domain.split('.')
    if len(domain) > 253 or len(labels) < 2 or not all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels
    ) or not re.search(r'[a-z]', labels[-1]):
        raise ValueError('Enter a domain, such as example.com, without a URL or path.')
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError('Enter a domain name rather than an IP address.')
