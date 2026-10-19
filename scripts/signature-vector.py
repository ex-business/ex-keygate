#!/usr/bin/env python3
"""Independently reproduce the public RFC 9421 profile test vector using Python stdlib."""
import base64
import hashlib
import hmac
import json
from pathlib import Path

components = ['@method', '@scheme', '@authority', '@path', '@query', 'content-digest',
              'content-type', 'x-keygate-client', 'x-keygate-key-version',
              'x-keygate-audience', 'x-keygate-environment', 'x-keygate-request-id']
body = b'{"probe":true}'
key = bytes(range(32))  # Public fixture material, never a runtime credential.
nonce = base64.urlsafe_b64encode(bytes(range(32, 64))).decode().rstrip('=')
params = '(' + ' '.join(json.dumps(c) for c in components) + ')'
params += ';created=1700000000;expires=1700000060;nonce="' + nonce + '";keyid="backend/1";alg="hmac-sha256";tag="ex-keygate-auth-v1"'
values = ['POST', 'https', 'example.com', '/a%2Fb', '?x=1&x=2&z=%2F',
          'sha-256=:' + base64.b64encode(hashlib.sha256(body).digest()).decode() + ':',
          'application/json', 'backend', '1', 'keygate-probe', 'test', 'vector-1']
base = '\n'.join(json.dumps(c) + ': ' + v for c, v in zip(components, values))
base += '\n"@signature-params": ' + params
headers = {c: v for c, v in zip(components, values) if not c.startswith('@')}
headers['signature-input'] = 'keygate=' + params
headers['signature'] = 'keygate=:' + base64.b64encode(hmac.new(key, base.encode(), hashlib.sha256).digest()).decode() + ':'
vector = dict(url='https://Example.COM:443/a%2Fb?x=1&x=2&z=%2F', method='POST',
              body=body.decode(), publicTestKey=base64.b64encode(key).decode(), headers=headers, base=base)
path = Path(__file__).resolve().parents[1] / 'internal/httpsign/testdata/vector.json'
if '--write' in __import__('sys').argv:
    path.write_text(json.dumps(vector, ensure_ascii=False, indent=2) + '\n')
else:
    assert json.loads(path.read_text()) == vector, 'Cross-language signature vector differs'
    print('Python RFC 9421 vector matches the committed fixture')
