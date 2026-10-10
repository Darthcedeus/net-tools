#!/usr/bin/env python3
"""Deterministic CLI fixture; never used by the production app."""
import json
import sys
import time

domain = sys.argv[sys.argv.index('-d') + 1]
if domain == 'failure.example':
    print('provider error: secret-must-never-reach-client', file=sys.stderr, flush=True)
    sys.exit(2)
if domain == 'slow.example':
    print('[crtsh] api.slow.example', file=sys.stderr, flush=True)
    time.sleep(10)
else:
    # Verbose per-source records arrive before the final aggregate JSON.
    print(f'[crtsh] api.{domain}', file=sys.stderr, flush=True)
    print('provider warning with secret-must-never-reach-client', file=sys.stderr, flush=True)
    time.sleep(0.15)
    for name, sources in [('api', ['crtsh', 'hackertarget']), ('docs', ['crtsh']), ('mail', ['hackertarget']), ('staging', ['crtsh', 'hackertarget']), ('www', ['crtsh'])]:
        print(json.dumps({'host': name + '.' + domain, 'input': domain, 'sources': sources}), flush=True)
        time.sleep(0.02)
    print(json.dumps({'host': 'API.' + domain.upper() + '.', 'sources': ['another']}), flush=True)
    print(json.dumps({'host': 'unrelated.example.net', 'sources': ['crtsh']}), flush=True)
    print('invalid JSON', flush=True)
