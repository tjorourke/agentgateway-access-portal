"""Explicit end-to-end checks against a configured portal and the test OIDC provider.

No bypass tokens: every client signs in through auth-code + PKCE and verified ID tokens.
"""
import argparse
import copy
import json
import subprocess
import time
from datetime import datetime, timedelta, timezone

import httpx


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--portal', default='http://localhost:9080')
    parser.add_argument('--issuer', required=True)
    parser.add_argument('--context', required=True)
    parser.add_argument('--namespace', default='access-portal')
    parser.add_argument('--restart-deployment', default='')
    args = parser.parse_args()
    clients = {}
    for role in ('admin', 'user', 'other'):
        client = httpx.Client(follow_redirects=True, timeout=90, limits=httpx.Limits(max_keepalive_connections=0))
        client.get(args.issuer + '/choose/' + role).raise_for_status()
        client.get(args.portal + '/auth/login').raise_for_status()
        session = client.get(args.portal + '/api/session').json()
        assert session['user']['role'] == ('admin' if role == 'admin' else 'user'), session
        client.headers.update({'Origin': args.portal, 'X-CSRF-Token': session['csrf']})
        clients[role] = client
    print('PASS real OIDC sign-in and group-based roles', flush=True)
    admin, user, other = (clients[r] for r in ('admin', 'user', 'other'))
    created = []
    original = admin.get(args.portal + '/api/admin/settings').json()['settings']

    def post(client, path, body):
        response = client.post(args.portal + path, json=body)
        data = response.json()
        assert response.is_success and data.get('ok'), (path, response.status_code, data.get('error'))
        return data

    def create(client):
        result = post(client, '/api/tokens', {'label': 'Integration check ' + str(time.time_ns()), 'models': original['lifecycle']['models'], 'ttlMinutes': 30})
        created.append(result['name'])
        return result

    def action(name, operation, body=None):
        return post(user, '/api/tokens/' + name + '/' + operation, body or {})

    def configure(updates):
        data = admin.get(args.portal + '/api/admin/settings').json()
        candidate = data['settings']
        for key, value in updates.items():
            candidate[key] = value
        return post(admin, '/api/admin/settings', {'settings': candidate, 'resourceVersion': data['resourceVersion']})

    def probe(name, generation, expected):
        for _ in range(15):
            got = action(name, 'test', {'generation': generation})
            if got['status'] == expected:
                print('PASS gateway HTTP', expected, flush=True)
                return
            time.sleep(.5)
        raise AssertionError(('gateway', expected, got['status']))

    def wait(name, condition, label):
        until = time.monotonic() + 100
        while time.monotonic() < until:
            data = user.get(args.portal + '/api/tokens').json()
            token = next(t for t in data['tokens'] if t['name'] == name)
            if condition(token):
                print('PASS', label, flush=True)
                return token
            time.sleep(2)
        raise AssertionError(label)

    def due(name, field):
        value = (datetime.now(timezone.utc) - timedelta(seconds=2)).isoformat()
        subprocess.run(['kubectl', '--context', args.context, '-n', args.namespace, 'patch',
                        'accesstokens.accessportal.io', name, '--type=merge', '-p', json.dumps({'spec': {field: value}})],
                       check=True, capture_output=True)

    try:
        first, second = create(user), create(other)
        assert 'trace' not in first
        inventory = user.get(args.portal + '/api/tokens').json()['tokens']
        assert all(t['name'] != second['name'] for t in inventory)
        assert user.post(args.portal + '/api/tokens/' + second['name'] + '/delete', json={}).status_code == 404
        assert user.get(args.portal + '/api/admin/settings').status_code == 403
        assert user.get(args.portal + '/api/policies').status_code == 403
        print('PASS ownership, admin-only settings and disabled employee views', flush=True)
        probe(first['name'], first['generation'], 200)
        rotate = action(first['name'], 'rotate')
        current = wait(first['name'], lambda t: t.get('pendingRotation'), 'manual rotation overlap')
        new_id = current['pendingRotation']['replacement']
        probe(first['name'], first['generation'], 200)
        probe(first['name'], new_id, 200)
        action(first['name'], 'complete', {'migrated': True})
        probe(first['name'], first['generation'], 401)
        probe(first['name'], new_id, 200)
        action(first['name'], 'update', {'label': 'Integration metadata updated', 'models': original['lifecycle']['models'], 'extendMinutes': 1})
        configure({'features': {'userTranscript': True, 'userPolicies': True}})
        assert user.get(args.portal + '/api/policies').status_code == 200
        revealed = action(first['name'], 'reveal')
        assert 'trace' in revealed and revealed['raw'] == rotate['raw']
        print('PASS day-two feature flags and metadata update', flush=True)
        configure({'lifecycle': {**original['lifecycle'], 'dailyTokenQuota': 100}})
        probe(first['name'], new_id, 429)
        configure({'lifecycle': original['lifecycle']})
        probe(first['name'], new_id, 200)
        if args.restart_deployment:
            subprocess.run(['kubectl', '--context', args.context, '-n', args.namespace, 'rollout', 'restart', 'deployment/' + args.restart_deployment], check=True)
            subprocess.run(['kubectl', '--context', args.context, '-n', args.namespace, 'rollout', 'status', 'deployment/' + args.restart_deployment, '--timeout=120s'], check=True)
            # Port-forwards tied to a replaced pod may need restarting externally;
            # use an Ingress or Service address when enabling this check.
            assert action(first['name'], 'reveal')['raw'] == rotate['raw']
            print('PASS encrypted values and OIDC sessions survive restart', flush=True)
        due(first['name'], 'rotatesAt')
        current = wait(first['name'], lambda t: t.get('pendingRotation'), 'scheduled rotation')
        replacement = current['pendingRotation']['replacement']
        probe(first['name'], replacement, 200)
        due(first['name'], 'expiresAt')
        wait(first['name'], lambda t: t['status'] == 'expired', 'scheduled expiry')
        probe(first['name'], replacement, 401)
        action(first['name'], 'renew')
        renewed = wait(first['name'], lambda t: t['status'] == 'active', 'renewal')
        probe(first['name'], renewed['generations'][-1]['id'], 200)
        probe(first['name'], replacement, 401)
        batch = post(user, '/api/bulk', {'names': [first['name'], second['name']], 'action': 'delete'})
        assert [r['ok'] for r in batch['results']] == [True, False]
        print('PASS mixed-owner bulk deletion', flush=True)
        policies = admin.get(args.portal + '/api/policies').json()['policies']
        assert policies and all(p['ready'] for p in policies), policies
        print('ALL LIVE CHECKS PASSED', flush=True)
    finally:
        data = admin.get(args.portal + '/api/admin/settings').json()
        post(admin, '/api/admin/settings', {'settings': original, 'resourceVersion': data['resourceVersion']})
        for name in created:
            admin.post(args.portal + '/api/tokens/' + name + '/delete', json={})


if __name__ == '__main__':
    main()
