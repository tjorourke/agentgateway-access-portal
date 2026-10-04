import copy
import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from portal.config import DEFAULTS
from portal.identity import Identity, owner_id, principal
from portal.kube import ApiError


def config():
    c = copy.deepcopy(DEFAULTS)
    c['auth'].update(issuer='https://id.example.test', clientId='portal')
    return c


def test_roles_only_follow_verified_group_mapping():
    c = config()
    claims = {'iss': c['auth']['issuer'], 'sub': 'person', 'groups': ['portal-users'], 'role': 'admin'}
    assert principal(claims, c)['role'] == 'user'
    claims['groups'] = ['portal-admins']
    assert principal(claims, c)['role'] == 'admin'
    claims['groups'] = 'portal-admins'
    with pytest.raises(ApiError):
        principal(claims, c)


def test_owner_identity_includes_issuer_and_subject():
    assert owner_id('issuer1', 'person') != owner_id('issuer2', 'person')
    assert owner_id('issuer1', 'person') == owner_id('issuer1', 'person')


@pytest.mark.parametrize('defect', [None, 'nonce', 'audience', 'issuer', 'expired', 'signature', 'state'])
@pytest.mark.parametrize('client_secret', ['', 'fixture-secret'])
def test_oidc_code_flow_signature_claims_and_pkce(defect, client_secret):
    c = config()
    identity = Identity('x' * 64, 'http://localhost:8080', client_secret)
    signing = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(signing.public_key()))
    jwk['kid'] = 'test-key'
    pending = {'state': 'state', 'nonce': 'nonce', 'verifier': 'v' * 43, 'issuer': c['auth']['issuer'], 'clientId': 'portal', 'expires': time.time() + 300}
    claims = {'iss': c['auth']['issuer'], 'sub': 'person', 'aud': 'portal', 'iat': int(time.time()),
              'exp': int(time.time()) + 300, 'nonce': 'nonce', 'groups': ['portal-admins']}
    if defect == 'nonce': claims['nonce'] = 'wrong'
    if defect == 'audience': claims['aud'] = 'different-client'
    if defect == 'issuer': claims['iss'] = 'https://other.example.test'
    if defect == 'expired': claims['exp'] = int(time.time()) - 100
    token = jwt.encode(claims, other if defect == 'signature' else signing, algorithm='RS256', headers={'kid': 'test-key'})
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.path.endswith('openid-configuration'):
            return httpx.Response(200, json={'issuer': c['auth']['issuer'], 'authorization_endpoint': c['auth']['issuer'] + '/authorize',
                'token_endpoint': c['auth']['issuer'] + '/token', 'jwks_uri': c['auth']['issuer'] + '/jwks'})
        if request.url.path == '/jwks': return httpx.Response(200, json={'keys': [jwk]})
        assert b'code_verifier=' in request.content and b'redirect_uri=' in request.content
        if client_secret:
            assert request.headers['authorization'].startswith('Basic ')
        return httpx.Response(200, json={'id_token': token})

    identity.http = httpx.Client(transport=httpx.MockTransport(handler))
    if defect:
        with pytest.raises(ApiError):
            identity.finish(c, identity.seal(pending), 'wrong' if defect == 'state' else 'state', 'code')
    else:
        result = identity.open(identity.finish(c, identity.seal(pending), 'state', 'code'))
        assert result['claims']['sub'] == 'person'
        assert principal(result['claims'], c)['role'] == 'admin'
    if defect == 'state': assert not seen


def test_cookie_tampering_and_expiry_fail_closed():
    identity = Identity('x' * 64, 'http://localhost:8080')
    cookie = identity.seal({'expires': time.time() + 10})
    assert identity.open(cookie)
    assert identity.open(cookie[:-3] + 'aaa') is None
    assert identity.open(identity.seal({'expires': time.time() - 1})) is None


def test_remote_plain_http_portal_is_rejected():
    with pytest.raises(RuntimeError):
        Identity('x' * 64, 'http://portal.example.com')
