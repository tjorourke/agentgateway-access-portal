import base64
import copy
import io
import json
import re
from urllib.parse import urlparse

from PIL import Image

from .kube import ApiError, core

DEFAULTS = {
    'configured': False,
    'branding': {'company': 'Your organisation', 'title': 'AI access tokens',
                 'subtitle': 'Manage access tokens for your applications.', 'accent': '#087f68', 'logo': ''},
    'auth': {'issuer': '', 'clientId': '', 'groupsClaim': 'groups',
             'adminGroups': ['portal-admins'], 'userGroups': ['portal-users'], 'allowAllAuthenticated': False},
    'features': {'userTranscript': False, 'userPolicies': False},
    'gateway': {'namespace': '', 'name': '', 'edition': 'enterprise', 'testURL': '', 'testModel': ''},
    'lifecycle': {'defaultExpiryMinutes': 1440, 'rotationMinutes': 720, 'automaticRotation': True,
                  'dailyTokenQuota': 100000, 'models': ['default']},
}


def merge(base, updates):
    if not isinstance(updates, dict):
        raise ApiError('Settings must be JSON objects.')
    result = copy.deepcopy(base)
    for key, value in updates.items():
        if key not in result:
            raise ApiError('Unknown setting: ' + key)
        result[key] = merge(result[key], value) if isinstance(result[key], dict) else value
    return result


def validate_profile(profile):
    if not isinstance(profile, dict):
        raise ApiError('Corporate profile must be a JSON object.')
    result = merge(DEFAULTS['branding'], profile)
    for key, maximum in [('company', 80), ('title', 100), ('subtitle', 240)]:
        if not isinstance(result[key], str) or not 1 <= len(result[key].strip()) <= maximum:
            raise ApiError(f'{key} must contain 1–{maximum} characters.')
        result[key] = result[key].strip()
    if not isinstance(result['accent'], str) or not re.fullmatch(r'#[0-9a-fA-F]{6}', result['accent']):
        raise ApiError('Accent must be a six-digit hex colour.')
    logo = result['logo']
    if not isinstance(logo, str) or len(logo) > 180000:
        raise ApiError('Logo must be smaller than 128 KB.')
    if logo:
        match = re.fullmatch(r'data:image/(png|jpeg|webp);base64,([A-Za-z0-9+/=]+)', logo)
        if not match:
            raise ApiError('Upload a PNG, JPEG or WebP logo. SVG/HTML is not accepted.')
        try:
            raw = base64.b64decode(match[2], validate=True)
            image = Image.open(io.BytesIO(raw))
            if image.width > 2048 or image.height > 2048 or image.format not in ('PNG', 'JPEG', 'WEBP'):
                raise ValueError('Unsupported image')
            image.verify()
            # Re-encode to remove uploaded metadata and trailing content.
            image = Image.open(io.BytesIO(raw)).convert('RGBA')
            image.thumbnail((320, 160))
            output = io.BytesIO()
            image.save(output, format='PNG')
            result['logo'] = 'data:image/png;base64,' + base64.b64encode(output.getvalue()).decode()
        except Exception as error:
            raise ApiError('The logo could not be decoded as a supported image.') from error
    return result


def validate(config, allowed_namespaces, allow_http=False):
    config = merge(DEFAULTS, config)
    config['branding'] = validate_profile(config['branding'])
    auth = config['auth']
    for field in ('issuer', 'clientId', 'groupsClaim'):
        if not isinstance(auth[field], str) or len(auth[field]) > 500:
            raise ApiError('Invalid OIDC ' + field)
    if auth['issuer'] and not (auth['issuer'].startswith('https://') or allow_http and auth['issuer'].startswith('http://')):
        raise ApiError('OIDC issuer must use HTTPS.')
    if auth['issuer']:
        parsed = urlparse(auth['issuer'])
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ApiError('OIDC issuer must not contain credentials, a query or a fragment.')
    if not auth['groupsClaim']:
        raise ApiError('Provide the group claim name.')
    if auth['groupsClaim'] in ('iss', 'sub', 'name', 'aud', 'exp', 'iat', 'nonce', 'preferred_username'):
        raise ApiError('The group claim cannot replace a reserved identity claim.')
    if type(config['configured']) is not bool:
        raise ApiError('configured must be a boolean.')
    for field in ('adminGroups', 'userGroups'):
        if not isinstance(auth[field], list) or not all(isinstance(g, str) and 0 < len(g) < 150 for g in auth[field]):
            raise ApiError(field + ' must be a list of group names.')
    if not auth['adminGroups']:
        raise ApiError('Configure at least one administrator group.')
    for flag in ('userTranscript', 'userPolicies'):
        if type(config['features'][flag]) is not bool:
            raise ApiError('Feature flags must be booleans.')
    if type(auth['allowAllAuthenticated']) is not bool:
        raise ApiError('allowAllAuthenticated must be a boolean.')
    gw = config['gateway']
    if not all(isinstance(gw[k], str) and len(gw[k]) <= 2048 for k in ('namespace', 'name', 'edition', 'testURL', 'testModel')):
        raise ApiError('Gateway settings must be strings.')
    if gw['namespace'] and gw['namespace'] not in allowed_namespaces:
        raise ApiError('Gateway namespace is outside the Helm-installed RBAC scope.')
    if gw['name'] and not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,62}', gw['name']):
        raise ApiError('Invalid Gateway name.')
    if gw['edition'] not in ('oss', 'enterprise'):
        raise ApiError('Choose OSS or Enterprise gateway.')
    lifecycle = config['lifecycle']
    for key, low, high in [('defaultExpiryMinutes', 1, 525600), ('rotationMinutes', 1, 525600), ('dailyTokenQuota', 100, 1000000000)]:
        if type(lifecycle[key]) is not int or not low <= lifecycle[key] <= high:
            raise ApiError(f'{key} must be between {low} and {high}.')
    if type(lifecycle['automaticRotation']) is not bool:
        raise ApiError('automaticRotation must be a boolean.')
    if not isinstance(lifecycle['models'], list) or not 1 <= len(lifecycle['models']) <= 100 or not all(isinstance(m, str) and 0 < len(m) <= 120 for m in lifecycle['models']):
        raise ApiError('Provide between 1 and 100 model names.')
    if config['configured'] and (not auth['issuer'] or not auth['clientId'] or not gw['name']):
        raise ApiError('Complete identity and gateway settings before finishing setup.')
    return config


class Settings:
    def __init__(self, kube, namespace, name):
        self.kube, self.namespace, self.name = kube, namespace, name

    def read(self):
        cm = self.kube.get(core(self.namespace, 'configmaps', self.name))
        return merge(DEFAULTS, json.loads(cm.get('data', {}).get('settings.json', '{}'))), cm['metadata']['resourceVersion']

    def write(self, config, version):
        existing = self.kube.get(core(self.namespace, 'configmaps', self.name))
        if existing['metadata']['resourceVersion'] != version:
            raise ApiError('Settings changed. Reload before saving.', 409)
        metadata = copy.deepcopy(existing['metadata'])
        metadata.pop('managedFields', None)
        return self.kube.call('PUT', core(self.namespace, 'configmaps', self.name), {
            'apiVersion': 'v1', 'kind': 'ConfigMap',
            'metadata': metadata,
            'data': {'settings.json': json.dumps(config)},
        })
