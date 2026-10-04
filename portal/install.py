"""Helm policy hooks and the minimal cluster clock. Never imports the web server."""
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import yaml

from .kube import ApiError, Kubernetes, core, selector, tokens

KINDS = {'GeneratingPolicy': 'generatingpolicies', 'MutatingPolicy': 'mutatingpolicies', 'ValidatingPolicy': 'validatingpolicies'}


def run(action, kube=None):
    kube = kube or Kubernetes()
    namespace, instance = os.environ['PORTAL_NAMESPACE'], os.environ['PORTAL_INSTANCE']
    if action == 'tick':
        kube.call('PATCH', core(namespace, 'configmaps', instance + '-clock'),
                  {'data': {'tick': datetime.now(timezone.utc).isoformat()}})
        print('Lifecycle clock updated.', flush=True)
        return
    bundle = kube.get(core(namespace, 'configmaps', instance + '-policy-bundle'))
    policies = [p for p in yaml.safe_load_all(bundle['data']['policies.yaml']) if p]
    if action == 'apply':
        deadline = time.monotonic() + int(os.getenv('INSTALL_TIMEOUT', '280'))
        for policy in policies:
            collection = '/apis/policies.kyverno.io/v1/' + KINDS[policy['kind']]
            while True:
                try:
                    kube.upsert(collection, policy['metadata']['name'], policy)
                    print('Applied', policy['kind'], policy['metadata']['name'], flush=True)
                    break
                except ApiError as error:
                    if time.monotonic() >= deadline or error.status in (400, 422):
                        raise RuntimeError('Policy installation failed. Kyverno 1.19 APIs and controller permissions are required. ' + str(error)) from error
                    time.sleep(3)
        for policy in policies:
            while time.monotonic() < deadline:
                value = kube.get('/apis/policies.kyverno.io/v1/' + KINDS[policy['kind']] + '/' + policy['metadata']['name'])
                if value.get('status', {}).get('conditionStatus', {}).get('ready'):
                    break
                time.sleep(2)
            else:
                raise RuntimeError('Policy did not become ready: ' + policy['metadata']['name'])
        # A compiler-ready policy is not proof that an existing Kyverno discovery
        # cache has picked up a newly installed CRD. Exercise an actual transition.
        probe_name = instance + '-installation-check'
        owner = 'u-' + '0' * 24
        stamp = datetime.now(timezone.utc)
        target_namespace = os.environ['GATEWAY_NAMESPACES'].split(',')[0]
        entry = json.dumps({'keyHash': 'sha256:' + '0' * 64,
                            'metadata': {'id': 'installation-check', 'user': owner, 'allowedModels': ['installation-check']}})
        probe = {'apiVersion': 'accessportal.io/v1alpha1', 'kind': 'AccessToken',
                 'metadata': {'name': probe_name, 'namespace': namespace, 'labels': {
                     'accessportal.io/instance': instance, 'accessportal.io/owner': owner, 'accessportal.io/healthcheck': 'true'}},
                 'spec': {'owner': owner, 'ownerName': 'Installation check', 'label': 'Installation check',
                          'status': 'active', 'models': ['installation-check'], 'createdAt': stamp.isoformat(),
                          'statusAt': stamp.isoformat(), 'expiresAt': (stamp - timedelta(seconds=1)).isoformat(),
                          'gatewayNamespace': target_namespace, 'gatewayName': 'installation-check', 'gatewayEdition': 'oss',
                          'pendingRotation': None, 'standby': None, 'rotatesAt': '',
                          'generations': [{'id': 'installation-check', 'entry': entry, 'status': 'active',
                                           'mintedAt': stamp.isoformat(), 'endedAt': None, 'by': 'installer'}]}}
        kube.call('DELETE', tokens(namespace, probe_name), missing=True)
        kube.call('POST', tokens(namespace), probe)
        try:
            while time.monotonic() < deadline:
                kube.call('PATCH', core(namespace, 'configmaps', instance + '-clock'), {'data': {'tick': datetime.now(timezone.utc).isoformat()}})
                time.sleep(2)
                record = kube.get(tokens(namespace, probe_name))
                cm = kube.get(core(target_namespace, 'configmaps', probe_name), missing=True)
                if record['spec']['status'] == 'expired' and cm and not cm.get('data'):
                    print('PASS live expiry and hash withdrawal. All portal policies ready.', flush=True)
                    break
            else:
                raise RuntimeError('Kyverno did not reconcile the installation probe. For an existing engine, enable admissionController.crdWatcher and refresh its admission/background controllers after installing a new CRD. Check policy events and controller logs.')
        finally:
            # The zero hash has no issued credential. Remove the synthetic record.
            kube.call('DELETE', tokens(namespace, probe_name), missing=True)
    elif action == 'cleanup':
        labels = selector(**{'accessportal.io/instance': instance})
        for obj in kube.get(tokens(namespace) + labels).get('items', []):
            obj['spec']['status'] = 'revoked'
            obj['spec']['pendingRotation'] = obj['spec']['standby'] = None
            obj['spec']['rotatesAt'] = ''
            for gen in obj['spec']['generations']:
                if gen['status'] in ('active', 'overlapping'):
                    gen['status'] = 'revoked'
            kube.call('PUT', tokens(namespace, obj['metadata']['name']), obj)
        for policy in reversed(policies):
            kube.call('DELETE', '/apis/policies.kyverno.io/v1/' + KINDS[policy['kind']] + '/' + policy['metadata']['name'], missing=True)
        for target in os.environ['GATEWAY_NAMESPACES'].split(','):
            for cm in kube.get(core(target, 'configmaps') + selector(**{'accessportal.io/instance': instance, 'accessportal.io/token-store': 'true'})).get('items', []):
                kube.call('DELETE', core(target, 'configmaps', cm['metadata']['name']), missing=True)
        for secret in kube.get(core(namespace, 'secrets') + labels).get('items', []):
            if secret['metadata']['name'].endswith('-values'):
                kube.call('DELETE', core(namespace, 'secrets', secret['metadata']['name']), missing=True)
        print('Token access withdrawn. Gateway authentication remains strict; history records retained.', flush=True)
    else:
        raise ValueError('Unknown action: ' + action)


if __name__ == '__main__':
    run(sys.argv[1])
