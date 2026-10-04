import base64
import copy
import hashlib
import json
import secrets
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx
from cryptography.fernet import Fernet, InvalidToken

from .kube import ApiError, core, selector, tokens


def now():
    return datetime.now(timezone.utc)


def iso(value):
    return value.isoformat().replace('+00:00', 'Z')


def current(spec):
    return next((g for g in reversed(spec['generations']) if g['status'] == 'active'), None)


class Store:
    def __init__(self, kube, namespace, instance, settings, encryption_key, allowed_namespaces, manage_gateway=True, enterprise_budgets=True):
        if len(encryption_key) < 32:
            raise RuntimeError('TOKEN_ENCRYPTION_KEY must contain at least 32 random characters.')
        self.kube, self.ns, self.instance, self.settings = kube, namespace, instance, settings
        self.allowed_namespaces, self.manage_gateway = allowed_namespaces, manage_gateway
        self.enterprise_budgets = enterprise_budgets
        self.cipher = Fernet(base64.urlsafe_b64encode(hashlib.sha256(encryption_key.encode()).digest()))
        self.http = httpx.Client(timeout=15, follow_redirects=False)

    def labels(self, owner=None):
        result = {'accessportal.io/instance': self.instance}
        if owner:
            result['accessportal.io/owner'] = owner
        return result

    def list(self, who):
        query = self.labels(who['id'] if who['role'] != 'admin' else None)
        rows = self.kube.get(tokens(self.ns) + selector(**query)).get('items', [])
        return [r for r in rows if r['metadata'].get('labels', {}).get('accessportal.io/instance') == self.instance
                and r['metadata'].get('labels', {}).get('accessportal.io/healthcheck') != 'true'
                and (who['role'] == 'admin' or r['spec']['owner'] == who['id'])]

    def owned(self, who, name):
        if not isinstance(name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,62}', name):
            raise ApiError('Token not found.', 404)
        obj = self.kube.get(tokens(self.ns, name), missing=True)
        if not obj or obj['metadata'].get('labels', {}).get('accessportal.io/instance') != self.instance or (
                who['role'] != 'admin' and obj['spec']['owner'] != who['id']):
            raise ApiError('Token not found.', 404)
        return obj

    def vault_name(self, name):
        return name + '-values'

    def load_values(self, name):
        secret = self.kube.get(core(self.ns, 'secrets', self.vault_name(name)), missing=True)
        values = {}
        for key, value in (secret or {}).get('data', {}).items():
            try:
                values[key] = self.cipher.decrypt(base64.b64decode(value)).decode()
            except (InvalidToken, ValueError):
                raise ApiError('Token storage cannot be decrypted. Check the installed encryption-key Secret.', 503)
        return values

    def save_values(self, name, owner, values, create=False):
        body = {'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
                'metadata': {'name': self.vault_name(name), 'namespace': self.ns, 'labels': self.labels(owner)},
                'data': {key: base64.b64encode(self.cipher.encrypt(value.encode())).decode() for key, value in values.items()}}
        if create:
            return self.kube.call('POST', core(self.ns, 'secrets'), body)
        previous = self.kube.get(core(self.ns, 'secrets', self.vault_name(name)))
        body['metadata']['resourceVersion'] = previous['metadata']['resourceVersion']
        body['data'] = {**previous.get('data', {}), **body['data']}
        return self.kube.call('PUT', core(self.ns, 'secrets', self.vault_name(name)), body)

    def mint(self, spec, values, actor):
        raw, gen = 'vk-' + secrets.token_urlsafe(32), 'g-' + secrets.token_hex(8)
        values[gen] = raw
        entry = {'keyHash': 'sha256:' + hashlib.sha256(raw.encode()).hexdigest(),
                 'metadata': {'id': gen, 'user': spec['owner'], 'group': self.instance,
                              'allowedModels': spec['models']}}
        return {'id': gen, 'entry': json.dumps(entry), 'mintedAt': iso(now()),
                'by': actor, 'status': 'active', 'endedAt': None}, raw

    def standby(self, spec, values):
        if not spec.get('standby') and spec['status'] == 'active' and not spec.get('pendingRotation'):
            generation, _ = self.mint(spec, values, 'policy')
            spec['standby'] = {'id': generation['id'], 'entry': generation['entry']}

    def schedule(self, spec, config):
        generation = current(spec)
        spec['rotatesAt'] = iso(datetime.fromisoformat(generation['mintedAt'].replace('Z', '+00:00')) +
                                timedelta(minutes=config['lifecycle']['rotationMinutes'])) if (
            generation and spec['status'] == 'active' and not spec.get('pendingRotation') and config['lifecycle']['automaticRotation']) else ''

    def save(self, obj, wait=True):
        name = obj['metadata']['name']
        obj.pop('status', None)
        obj['metadata'].pop('managedFields', None)
        result = self.kube.call('PUT' if obj['metadata'].get('resourceVersion') else 'POST',
                                tokens(self.ns, name if obj['metadata'].get('resourceVersion') else ''), obj)
        if wait:
            self.wait(result)
        return result

    def wait(self, obj, timeout=20):
        spec = obj['spec']
        expected = {g['id']: g['entry'] for g in spec['generations'] if g['status'] in ('active', 'overlapping')} if spec['status'] == 'active' else {}
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            cm = self.kube.get(core(spec['gatewayNamespace'], 'configmaps', obj['metadata']['name']), missing=True)
            if cm and (cm.get('data') or {}) == expected:
                return
            time.sleep(.25)
        raise ApiError('Record saved; gateway reconciliation is still pending. Check the configured lifecycle controller.', 503)

    def event(self, who, obj, reason, message):
        body = {'apiVersion': 'v1', 'kind': 'Event',
                'metadata': {'generateName': self.instance + '-', 'namespace': self.ns,
                             'labels': {**self.labels(obj['spec']['owner']), 'accessportal.io/token': obj['metadata']['name'],
                                        'accessportal.io/actor': who['id']}},
                'involvedObject': {'apiVersion': 'accessportal.io/v1alpha1', 'kind': 'AccessToken',
                                   'namespace': self.ns, 'name': obj['metadata']['name'], 'uid': obj['metadata']['uid']},
                'reason': reason, 'message': who['name'] + ': ' + message, 'type': 'Normal',
                'reportingComponent': 'accessportal', 'reportingInstance': self.instance,
                'action': reason, 'firstTimestamp': iso(now()), 'lastTimestamp': iso(now()), 'count': 1}
        self.kube.call('POST', core(self.ns, 'events'), body)

    def create(self, who, body, config):
        label = str(body.get('label', '')).strip()
        if not 1 <= len(label) <= 80:
            raise ApiError('Enter an application name, up to 80 characters.')
        models = body.get('models') or []
        if not isinstance(models, list) or not models or not all(isinstance(m, str) for m in models) or not set(models) <= set(config['lifecycle']['models']):
            raise ApiError('Select at least one configured model.')
        ttl = body.get('ttlMinutes', config['lifecycle']['defaultExpiryMinutes'])
        if type(ttl) is not int or not 1 <= ttl <= 525600:
            raise ApiError('Expiry must be between one minute and one year.')
        gw = config['gateway']
        name = self.instance[:25] + '-' + secrets.token_hex(8)
        spec = {'owner': who['id'], 'ownerName': who['name'], 'label': label, 'models': list(dict.fromkeys(models)),
                'status': 'active', 'createdAt': iso(now()), 'statusAt': iso(now()),
                'expiresAt': iso(now() + timedelta(minutes=ttl)), 'pendingRotation': None, 'standby': None,
                'gatewayNamespace': gw['namespace'], 'gatewayName': gw['name'], 'gatewayEdition': gw['edition'], 'generations': []}
        values = {}
        generation, raw = self.mint(spec, values, who['name'])
        spec['generations'].append(generation)
        self.standby(spec, values)
        self.schedule(spec, config)
        self.save_values(name, who['id'], values, create=True)
        obj = self.save({'apiVersion': 'accessportal.io/v1alpha1', 'kind': 'AccessToken',
                         'metadata': {'name': name, 'namespace': self.ns, 'labels': self.labels(who['id'])}, 'spec': spec})
        self.event(who, obj, 'TokenCreated', 'requested ' + label)
        return {'name': name, 'raw': raw, 'generation': generation['id']}

    def probe(self, raw, config, models=None):
        gateway = config['gateway']
        if not gateway['testURL']:
            raise ApiError('Configure a gateway test endpoint in Settings before verifying a token.')
        models = models or config['lifecycle']['models']
        model = gateway['testModel'] if gateway['testModel'] in models else models[0]
        start = time.monotonic()
        try:
            response = self.http.post(gateway['testURL'].rstrip('/') + '/v1/chat/completions',
                 headers={'Authorization': 'Bearer ' + raw},
                 json={'model': model, 'messages': [{'role': 'user', 'content': 'Reply OK.'}], 'max_tokens': 1})
            return {'status': response.status_code, 'ms': round((time.monotonic() - start) * 1000), 'model': model}
        except httpx.HTTPError as error:
            raise ApiError('Gateway test endpoint is unavailable.', 502) from error

    def verified(self, raw, config, models=None):
        for _ in range(8):
            result = self.probe(raw, config, models)
            if result['status'] == 200:
                return
            if result['status'] not in (401, 403):
                break
            time.sleep(.5)
        raise ApiError('Replacement did not pass the gateway check. Existing values have not been retired.', 409)

    def action(self, who, name, action, body, config):
        obj = self.owned(who, name)
        before = copy.deepcopy(obj)
        spec = obj['spec']
        needs_values = action in ('test', 'reveal', 'renew', 'rotate', 'complete')
        values = self.load_values(name) if needs_values else {}
        result = {}
        if action == 'test':
            gen = next((g for g in spec['generations'] if g['id'] == body.get('generation')), None) if body.get('generation') else (current(spec) or spec['generations'][-1])
            if not gen or gen['id'] not in values:
                raise ApiError('Generation value unavailable.', 404)
            result = self.probe(values[gen['id']], config, json.loads(gen['entry'])['metadata']['allowedModels'])
        elif action == 'reveal':
            gen = current(spec)
            if spec['status'] != 'active' or not gen or gen['id'] not in values:
                raise ApiError('No active token value is available.')
            result = {'raw': values[gen['id']]}
        elif action == 'renew':
            if spec['status'] != 'expired':
                raise ApiError('Only expired tokens can be renewed.')
            if (spec['gatewayNamespace'], spec['gatewayName']) != (config['gateway']['namespace'], config['gateway']['name']):
                raise ApiError('This record belongs to a previous gateway. Request a new token for the current gateway.', 409)
            spec['status'], spec['statusAt'] = 'active', iso(now())
            spec['expiresAt'] = iso(now() + timedelta(minutes=config['lifecycle']['defaultExpiryMinutes']))
            spec['pendingRotation'] = spec['standby'] = None
            generation, raw = self.mint(spec, values, who['name'])
            spec['generations'].append(generation)
            self.standby(spec, values)
            self.schedule(spec, config)
            result = {'raw': raw}
        elif action == 'rotate':
            if spec['status'] != 'active' or spec.get('pendingRotation'):
                raise ApiError('Token must be active with no handover pending.')
            old = current(spec)
            generation, raw = self.mint(spec, values, who['name'])
            old['status'] = 'overlapping'
            spec['generations'].append(generation)
            spec['pendingRotation'] = {'previous': old['id'], 'replacement': generation['id'], 'preparedAt': iso(now()), 'verified': False}
            spec['standby'], spec['rotatesAt'] = None, ''
            self.save_values(name, spec['owner'], values)
            obj = self.save(obj)
            try:
                self.verified(raw, config, spec['models'])
            except ApiError:
                before['metadata']['resourceVersion'] = obj['metadata']['resourceVersion']
                self.save(before)
                raise
            spec = obj['spec']
            spec['pendingRotation']['verified'] = True
            result = {'raw': raw, 'pendingRotation': True}
        elif action == 'complete':
            pending = spec.get('pendingRotation')
            if spec['status'] != 'active' or not pending or body.get('migrated') is not True:
                raise ApiError('Confirm that applications have migrated before completing rotation.')
            if pending['replacement'] not in values:
                raise ApiError('Replacement value is unavailable. Existing values have not been retired.', 409)
            self.verified(values[pending['replacement']], config, spec['models'])
            for gen in spec['generations']:
                if gen['status'] == 'overlapping':
                    gen['status'], gen['endedAt'] = 'superseded', iso(now())
            spec['pendingRotation'] = None
            self.standby(spec, values)
            self.schedule(spec, config)
        elif action in ('revoke', 'delete'):
            if spec['status'] == 'active':
                spec['status'], spec['statusAt'] = 'revoked', iso(now())
                spec['standby'] = spec['pendingRotation'] = None
                spec['rotatesAt'] = ''
                for gen in spec['generations']:
                    if gen['status'] in ('active', 'overlapping'):
                        gen['status'], gen['endedAt'] = 'revoked', iso(now())
        elif action == 'update':
            if spec['status'] != 'active':
                raise ApiError('Only active token settings can be changed.')
            label, models = body.get('label', spec['label']), body.get('models', spec['models'])
            if not isinstance(label, str) or not 1 <= len(label.strip()) <= 80 or not isinstance(models, list) or not models or not all(isinstance(m, str) for m in models) or not set(models) <= set(config['lifecycle']['models']):
                raise ApiError('Provide a name and valid model permissions.')
            spec['label'], spec['models'] = label.strip(), list(dict.fromkeys(models))
            for gen in spec['generations'] + ([spec['standby']] if spec.get('standby') else []):
                if gen.get('status', 'active') in ('active', 'overlapping'):
                    entry = json.loads(gen['entry'])
                    entry['metadata']['allowedModels'] = spec['models']
                    gen['entry'] = json.dumps(entry)
            extension = body.get('extendMinutes', 0)
            if type(extension) is not int or not 0 <= extension <= 525600:
                raise ApiError('Invalid expiry extension.')
            if extension:
                spec['expiresAt'] = iso(max(now(), datetime.fromisoformat(spec['expiresAt'].replace('Z', '+00:00'))) + timedelta(minutes=extension))
        else:
            raise ApiError('Unknown token action.')
        if action not in ('test', 'reveal'):
            if needs_values:
                self.save_values(name, spec['owner'], values)
            obj = self.save(obj)
        self.event(who, obj, 'Token' + action.title(), action + ' ' + spec['label'])
        if action == 'delete':
            self.kube.call('DELETE', tokens(self.ns, name), {'apiVersion': 'v1', 'kind': 'DeleteOptions',
                'preconditions': {'resourceVersion': obj['metadata']['resourceVersion']}})
            self.kube.call('DELETE', core(self.ns, 'secrets', self.vault_name(name)), missing=True)
        return {'name': name, **result}

    def discover(self):
        classes = self.kube.get('/apis/gateway.networking.k8s.io/v1/gatewayclasses').get('items', [])
        eligible = {c['metadata']['name']: c['spec']['controllerName'] for c in classes if 'agentgateway' in c['spec']['controllerName']}
        result = []
        for namespace in self.allowed_namespaces:
            gateways = self.kube.get(f'/apis/gateway.networking.k8s.io/v1/namespaces/{namespace}/gateways').get('items', [])
            services = self.kube.get(core(namespace, 'services')).get('items', [])
            for gateway in gateways:
                name, klass = gateway['metadata']['name'], gateway['spec']['gatewayClassName']
                if klass not in eligible:
                    continue
                edition = 'enterprise' if 'enterprise' in eligible[klass] else 'oss'
                group = 'enterpriseagentgateway.solo.io' if edition == 'enterprise' else 'agentgateway.dev'
                plural = 'enterpriseagentgatewaypolicies' if edition == 'enterprise' else 'agentgatewaypolicies'
                policies = (self.kube.get(f'/apis/{group}/v1alpha1/namespaces/{namespace}/{plural}', missing=True) or {}).get('items', [])
                conflicts = [p['metadata']['name'] for p in policies if p['metadata'].get('labels', {}).get('accessportal.io/instance') != self.instance
                             and p.get('spec', {}).get('traffic', {}).get('apiKeyAuthentication')
                             and any(t.get('kind') == 'Gateway' and t.get('name') == name for t in p.get('spec', {}).get('targetRefs', []))]
                service = next((s for s in services if s['metadata'].get('labels', {}).get('gateway.networking.k8s.io/gateway-name') == name or s['metadata']['name'] == name), None)
                listener = next((l for l in gateway['spec'].get('listeners', []) if l.get('protocol') == 'HTTP'), None)
                test_url = f"http://{service['metadata']['name']}.{namespace}.svc.cluster.local:{listener['port']}" if service and listener else ''
                result.append({'namespace': namespace, 'name': name, 'class': klass, 'edition': edition,
                               'testURL': test_url, 'conflicts': conflicts,
                               'ready': any(c.get('type') == 'Programmed' and c.get('status') == 'True' for c in gateway.get('status', {}).get('conditions', []))})
        return result

    def configure_gateway(self, config):
        gw = config['gateway']
        found = next((g for g in self.discover() if g['namespace'] == gw['namespace'] and g['name'] == gw['name']), None)
        if not found:
            raise ApiError('Choose a discovered agentgateway Gateway in the allowed namespaces.')
        if found['edition'] != gw['edition']:
            raise ApiError('Gateway edition does not match discovery.')
        if self.manage_gateway and found['conflicts']:
            raise ApiError('This Gateway already has an API-key authentication policy: ' + ', '.join(found['conflicts']) + '. Select a dedicated Gateway or manage its policy externally.', 409)
        if gw['testURL']:
            parsed = urlparse(gw['testURL'])
            if parsed.scheme not in ('http', 'https') or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ApiError('Provide an HTTP(S) gateway base URL without credentials, query or fragment.')
        if gw['testModel'] and gw['testModel'] not in config['lifecycle']['models']:
            raise ApiError('The test model must be included in the configured model list.')
        if not self.manage_gateway:
            return
        enterprise = gw['edition'] == 'enterprise'
        group = 'enterpriseagentgateway.solo.io' if enterprise else 'agentgateway.dev'
        kind = 'EnterpriseAgentgatewayPolicy' if enterprise else 'AgentgatewayPolicy'
        plural = 'enterpriseagentgatewaypolicies' if enterprise else 'agentgatewaypolicies'
        name = self.instance + '-access'
        traffic = {'apiKeyAuthentication': {'mode': 'Strict', 'configMapSelector': {'matchLabels': {**self.labels(), 'accessportal.io/token-store': 'true'}}},
                   'authorization': {'action': 'Allow', 'policy': {'matchExpressions': ['json(request.body).model in apiKey.allowedModels']}}}
        if enterprise and self.enterprise_budgets:
            traffic['entBudgetEnforcement'] = {}
        self.kube.upsert(f'/apis/{group}/v1alpha1/namespaces/{gw["namespace"]}/{plural}', name, {
            'apiVersion': group + '/v1alpha1', 'kind': kind,
            'metadata': {'name': name, 'namespace': gw['namespace'], 'labels': self.labels()},
            'spec': {'targetRefs': [{'group': 'gateway.networking.k8s.io', 'kind': 'Gateway', 'name': gw['name']}], 'traffic': traffic}})

    def permissions(self):
        checks = []
        for namespace, group, resource, verb in [(self.ns, 'accessportal.io', 'accesstokens', 'create'),
                (self.ns, '', 'configmaps', 'update'), (self.ns, '', 'secrets', 'create')] + [
                (ns, 'gateway.networking.k8s.io', 'gateways', 'list') for ns in self.allowed_namespaces]:
            review = self.kube.call('POST', '/apis/authorization.k8s.io/v1/selfsubjectaccessreviews', {
                'apiVersion': 'authorization.k8s.io/v1', 'kind': 'SelfSubjectAccessReview',
                'spec': {'resourceAttributes': {'namespace': namespace, 'group': group, 'resource': resource, 'verb': verb,
                                               **({'name': self.settings.name} if resource == 'configmaps' else {})}}})
            checks.append({'namespace': namespace, 'resource': resource, 'verb': verb, 'allowed': review.get('status', {}).get('allowed', False)})
        return checks
