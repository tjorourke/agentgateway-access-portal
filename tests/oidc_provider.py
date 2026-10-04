"""Test-only OIDC provider with real RSA signatures and PKCE. Never part of Helm defaults."""
import base64
import hashlib
import json
import os
import secrets
import time
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, redirect, request

app = Flask(__name__)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
jwk.update(kid='fixture', use='sig', alg='RS256')
codes = {}
REDIRECT = os.getenv('TEST_REDIRECT_URI', 'http://localhost:9080/auth/callback')


@app.get('/.well-known/openid-configuration')
def discovery():
    base = request.host_url.rstrip('/')
    return jsonify(issuer=base, authorization_endpoint=base+'/authorize', token_endpoint=base+'/token',
                   jwks_uri=base+'/jwks', response_types_supported=['code'], subject_types_supported=['public'],
                   id_token_signing_alg_values_supported=['RS256'], code_challenge_methods_supported=['S256'])


@app.get('/jwks')
def jwks():
    return jsonify(keys=[jwk])


@app.get('/choose/<role>')
def choose(role):
    if role not in ('admin', 'user', 'other'):
        return 'Unknown fixture role', 400
    response = jsonify(ok=True)
    response.set_cookie('fixture_role', role)
    return response


@app.get('/authorize')
def authorize():
    p = request.args
    if p.get('client_id') != 'portal-e2e' or p.get('redirect_uri') != REDIRECT or p.get('code_challenge_method') != 'S256':
        return 'Invalid fixture client', 400
    code = secrets.token_urlsafe(32)
    codes[code] = {'nonce': p['nonce'], 'challenge': p['code_challenge'], 'role': request.cookies.get('fixture_role', 'admin'), 'expires': time.time()+60}
    return redirect(REDIRECT + '?' + urlencode({'code': code, 'state': p['state']}))


@app.post('/token')
def token():
    code = codes.pop(request.form.get('code'), None)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(request.form.get('code_verifier', '').encode()).digest()).rstrip(b'=').decode()
    if not code or code['expires'] < time.time() or challenge != code['challenge'] or request.form.get('client_id') != 'portal-e2e' or request.form.get('redirect_uri') != REDIRECT:
        return jsonify(error='invalid_grant'), 400
    role = code['role']
    claims = {'iss': request.host_url.rstrip('/'), 'sub': 'fixture-'+role, 'aud': 'portal-e2e', 'iat': int(time.time()),
              'exp': int(time.time())+900, 'nonce': code['nonce'], 'name': 'Platform administrator' if role=='admin' else 'Test employee',
              'groups': ['portal-admins'] if role=='admin' else ['portal-users']}
    return jsonify(id_token=jwt.encode(claims, key, algorithm='RS256', headers={'kid':'fixture'}), access_token='unused-fixture-access-token', token_type='Bearer')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8090)
