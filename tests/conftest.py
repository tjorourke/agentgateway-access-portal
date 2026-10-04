import copy
import json
import time
from urllib.parse import parse_qs

import pytest

from portal.config import DEFAULTS
from portal.kube import ApiError, TRACE, core
from portal.web import create_app


class FakeKube:
    def __init__(self, configured=True):
        self.objects = {}
        self.calls = []
        self.version = 0
        config = copy.deepcopy(DEFAULTS)
        config['configured'] = configured
        config['auth'].update(issuer='https://id.example.test', clientId='portal')
        config['gateway'].update(namespace='gateways', name='ai', edition='enterprise',
                                 testURL='https://gateway.example.test', testModel='default')
        self.save(core('portal', 'configmaps', 'instance-settings'), {'apiVersion': 'v1', 'kind': 'ConfigMap',
                  'metadata': {'name': 'instance-settings', 'namespace': 'portal'}, 'data': {'settings.json': json.dumps(config)}})

    def save(self, path, value):
        self.version += 1
        value = copy.deepcopy(value)
        value.setdefault('metadata', {})['resourceVersion'] = str(self.version)
        value['metadata'].setdefault('uid', 'uid-' + str(self.version))
        value['metadata'].setdefault('creationTimestamp', '2026-01-01T00:00:00Z')
        self.objects[path] = value
        return copy.deepcopy(value)

    def get(self, path, missing=False):
        return self.call('GET', path, missing=missing)

    def call(self, method, path, body=None, missing=False, **kwargs):
        self.calls.append((method, path, copy.deepcopy(body)))
        if TRACE.get() is not None:
            TRACE.get().append({'method': method, 'path': path, 'status': 200, 'body': None})
        base, _, query = path.partition('?')
        if method == 'GET':
            if base in self.objects:
                return copy.deepcopy(self.objects[base])
            labels = dict(kv.split('=', 1) for kv in parse_qs(query).get('labelSelector', [''])[0].split(',') if '=' in kv)
            items = [copy.deepcopy(v) for p, v in self.objects.items() if p.rsplit('/', 1)[0] == base
                     and all(v['metadata'].get('labels', {}).get(k) == val for k, val in labels.items())]
            if items or base.rsplit('/', 1)[-1] in ('accesstokens', 'events', 'secrets', 'configmaps', 'gateways', 'services', 'gatewayclasses'):
                return {'items': items}
            if missing:
                return None
            raise ApiError('Not found', 404)
        if method == 'POST' and base.endswith('selfsubjectaccessreviews'):
            return {'status': {'allowed': True}}
        if method == 'POST':
            body = copy.deepcopy(body)
            name = body['metadata'].get('name') or body['metadata']['generateName'] + str(self.version)
            body['metadata']['name'] = name
            target = base + '/' + name
            if target in self.objects:
                raise ApiError('Conflict', 409)
            result = self.save(target, body)
        elif method == 'PUT':
            if base not in self.objects:
                raise ApiError('Not found', 404)
            if body['metadata']['resourceVersion'] != self.objects[base]['metadata']['resourceVersion']:
                raise ApiError('Conflict', 409)
            result = self.save(base, body)
        elif method == 'DELETE':
            self.objects.pop(base, None)
            return {}
        else:
            raise AssertionError(method)
        if result.get('kind') == 'AccessToken':
            spec = result['spec']
            self.save(core(spec['gatewayNamespace'], 'configmaps', result['metadata']['name']), {
                'metadata': {'name': result['metadata']['name']},
                'data': {g['id']: g['entry'] for g in spec['generations'] if g['status'] in ('active', 'overlapping') and spec['status'] == 'active'}})
        return result

    def upsert(self, collection, name, body):
        previous = self.get(collection + '/' + name, missing=True)
        if previous:
            body['metadata']['resourceVersion'] = previous['metadata']['resourceVersion']
            return self.call('PUT', collection + '/' + name, body)
        return self.call('POST', collection, body)


@pytest.fixture
def kube():
    return FakeKube()


@pytest.fixture
def app(kube):
    return create_app(kube, {'TESTING': True, 'PORTAL_NAMESPACE': 'portal', 'PORTAL_INSTANCE': 'instance',
        'SESSION_KEY': 's' * 64, 'TOKEN_ENCRYPTION_KEY': 'e' * 64, 'BOOTSTRAP_TOKEN': 'b' * 64,
        'PUBLIC_URL': 'http://localhost:8080', 'GATEWAY_NAMESPACES': 'gateways'})


def login(client, app, subject='employee-1', groups=None):
    claims = {'iss': 'https://id.example.test', 'sub': subject, 'name': subject,
              'groups': groups if groups is not None else ['portal-users'], 'exp': time.time() + 3600}
    value = app.extensions['identity'].seal({'claims': claims, 'csrf': 'test-csrf', 'expires': time.time() + 3600})
    client.set_cookie('portal_session', value)
    return {'X-CSRF-Token': 'test-csrf', 'Origin': 'http://localhost:8080'}
