import base64
import hashlib
import json
import secrets
import time
from urllib.parse import urlencode, urlparse

import httpx
import jwt
from cryptography.fernet import Fernet, InvalidToken

from .kube import ApiError


def owner_id(issuer, subject):
    return 'u-' + hashlib.sha256((issuer + '\0' + subject).encode()).hexdigest()[:24]


def principal(claims, config):
    auth = config['auth']
    if claims.get('iss') != auth['issuer'] or not isinstance(claims.get('sub'), str) or not claims['sub']:
        raise ApiError('Identity issuer or subject is invalid.', 401)
    groups = claims.get(auth['groupsClaim'], [])
    if not isinstance(groups, list) or not all(isinstance(g, str) for g in groups):
        groups = []
    admin = bool(set(groups) & set(auth['adminGroups']))
    if not admin and not auth['allowAllAuthenticated'] and not set(groups) & set(auth['userGroups']):
        raise ApiError('Your identity is not in an allowed portal group.', 403)
    return {'id': owner_id(auth['issuer'], claims['sub']), 'name': str(claims.get('name') or claims.get('preferred_username') or claims['sub'])[:128],
            'role': 'admin' if admin else 'user'}


class Identity:
    def __init__(self, session_key, public_url, client_secret='', session_seconds=3600):
        if len(session_key) < 32:
            raise RuntimeError('SESSION_KEY must contain at least 32 random characters.')
        self.cipher = Fernet(base64.urlsafe_b64encode(hashlib.sha256(session_key.encode()).digest()))
        self.public_url = public_url.rstrip('/')
        parsed = urlparse(self.public_url)
        if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in ('localhost', '127.0.0.1', '::1')):
            raise RuntimeError('PUBLIC_URL must use HTTPS, except for loopback development URLs.')
        self.client_secret, self.session_seconds = client_secret, session_seconds
        self.http = httpx.Client(timeout=10, follow_redirects=False)

    def seal(self, value):
        return self.cipher.encrypt(json.dumps(value).encode()).decode()

    def open(self, value, age=3600):
        try:
            payload = json.loads(self.cipher.decrypt(value.encode(), ttl=age))
            if payload.get('expires', 0) < time.time():
                return None
            return payload
        except (InvalidToken, ValueError, TypeError):
            return None

    def discovery(self, issuer):
        try:
            data = self.http.get(issuer.rstrip('/') + '/.well-known/openid-configuration').raise_for_status().json()
        except (httpx.HTTPError, ValueError) as error:
            raise ApiError('Unable to load the OIDC provider configuration.', 502) from error
        if not isinstance(data, dict) or data.get('issuer') != issuer:
            raise ApiError('OIDC discovery issuer does not match the configured issuer.')
        for key in ('authorization_endpoint', 'token_endpoint', 'jwks_uri'):
            if not isinstance(data.get(key), str) or not data[key].startswith(('https://', 'http://')):
                raise ApiError('OIDC discovery is missing ' + key)
            if issuer.startswith('https://') and not data[key].startswith('https://'):
                raise ApiError('HTTPS identity providers must expose HTTPS endpoints.')
        return data

    def start(self, config):
        auth = config['auth']
        discovery = self.discovery(auth['issuer'])
        verifier = secrets.token_urlsafe(48)
        payload = {'state': secrets.token_urlsafe(32), 'nonce': secrets.token_urlsafe(32), 'verifier': verifier,
                   'issuer': auth['issuer'], 'clientId': auth['clientId'], 'expires': time.time() + 300}
        params = {'response_type': 'code', 'client_id': auth['clientId'], 'redirect_uri': self.public_url + '/auth/callback',
                  'scope': 'openid profile email', 'state': payload['state'], 'nonce': payload['nonce'],
                  'code_challenge': base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode(),
                  'code_challenge_method': 'S256'}
        return discovery['authorization_endpoint'] + '?' + urlencode(params), self.seal(payload)

    def finish(self, config, transaction, state, code):
        pending = self.open(transaction or '', 300)
        if not pending or not secrets.compare_digest(pending['state'], state or ''):
            raise ApiError('Invalid or expired login state.', 401)
        auth = config['auth']
        if pending['issuer'] != auth['issuer'] or pending['clientId'] != auth['clientId']:
            raise ApiError('Identity settings changed. Start sign-in again.', 401)
        discovery = self.discovery(auth['issuer'])
        data = {'grant_type': 'authorization_code', 'code': code, 'client_id': auth['clientId'],
                'redirect_uri': self.public_url + '/auth/callback', 'code_verifier': pending['verifier']}
        client_auth = None
        if self.client_secret:
            methods = discovery.get('token_endpoint_auth_methods_supported', ['client_secret_basic'])
            if 'client_secret_post' in methods:
                data['client_secret'] = self.client_secret
            elif 'client_secret_basic' in methods:
                client_auth = httpx.BasicAuth(auth['clientId'], self.client_secret)
            else:
                raise ApiError('The provider does not support this client-secret authentication method.')
        try:
            result = self.http.post(discovery['token_endpoint'], data=data, auth=client_auth).raise_for_status().json()
            jwks = self.http.get(discovery['jwks_uri']).raise_for_status().json()
            header = jwt.get_unverified_header(result['id_token'])
            if header.get('alg') not in ('RS256', 'ES256'):
                raise ValueError('Unsupported ID token algorithm')
            key_data = next(k for k in jwks['keys'] if k.get('kid') == header.get('kid'))
            key = jwt.PyJWK.from_dict(key_data).key
            claims = jwt.decode(result['id_token'], key, algorithms=[header['alg']], audience=auth['clientId'],
                                issuer=auth['issuer'], options={'require': ['exp', 'iat', 'iss', 'aud', 'sub', 'nonce']})
            if not secrets.compare_digest(claims['nonce'], pending['nonce']):
                raise ValueError('Nonce mismatch')
            if isinstance(claims['aud'], list) and len(claims['aud']) > 1 and claims.get('azp') != auth['clientId']:
                raise ValueError('Authorised party mismatch')
        except (httpx.HTTPError, KeyError, ValueError, TypeError, StopIteration, jwt.PyJWTError) as error:
            raise ApiError('The identity provider response could not be verified.', 401) from error
        who = principal(claims, config)
        if len(claims['sub']) > 255:
            raise ApiError('OIDC subject exceeds the supported length.', 401)
        # Do not copy every directory group, email or provider-specific claim into
        # the session cookie. Keep only identity and groups relevant to this app.
        relevant = set(auth['adminGroups']) | set(auth['userGroups'])
        groups = claims.get(auth['groupsClaim'], [])
        minimal = {'iss': claims['iss'], 'sub': claims['sub'], 'name': who['name'],
                   auth['groupsClaim']: [g for g in groups if isinstance(g, str) and g in relevant] if isinstance(groups, list) else []}
        value = self.seal({'claims': minimal, 'csrf': secrets.token_urlsafe(24),
                           'expires': min(claims['exp'], time.time() + self.session_seconds)})
        if len(value) > 3800:
            raise ApiError('Portal group mappings are too large for a session. Use dedicated application groups.', 401)
        return value
