#!/usr/bin/env python3
"""Generate a private Compose .env without persisting a plaintext password."""
import getpass
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.security import hash_password


def main():
    destination = ROOT / '.env'
    if destination.exists():
        if input('.env already exists. Replace it and change the password? [y/N] ').strip().lower() != 'y':
            print('Kept the existing configuration.')
            return
    origin = input('Public URL (e.g. https://subfinder.example.com): ').strip().rstrip('/')
    parsed = urlsplit(origin)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc or parsed.path or parsed.query or parsed.fragment or parsed.username or any(c in origin for c in "'\"\n\r"):
        sys.exit('Enter a complete origin with no path, credentials, or query string.')
    if parsed.scheme == 'http' and parsed.hostname not in ('localhost', '127.0.0.1', '::1'):
        sys.exit('Use HTTPS for internet access. HTTP is only supported for localhost development.')
    password = getpass.getpass('Choose a password (at least 12 characters): ')
    if len(password) < 12:
        sys.exit('Choose a password with at least 12 characters.')
    if password != getpass.getpass('Confirm password: '):
        sys.exit('Passwords did not match.')
    encoded = hash_password(password)
    # Single-quoted dotenv values preserve PBKDF2 dollar signs through Compose.
    contents = f"APP_ORIGIN='{origin}'\nAPP_PASSWORD_HASH='{encoded}'\n"
    os.umask(0o077)
    temporary = destination.with_name('.env.setup-tmp')
    with open(temporary, 'w', encoding='utf-8') as file:
        file.write(contents)
    os.chmod(temporary, 0o600)
    os.replace(temporary, destination)
    print('Saved .env (permissions 0600). Your plaintext password was not saved.')
    print('Start the app: docker compose up -d --build')


if __name__ == '__main__':
    main()
