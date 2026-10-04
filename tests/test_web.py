import copy
import json

import pytest

from portal.config import DEFAULTS, validate, validate_profile
from portal.kube import core
from conftest import login


def test_unauthenticated_and_csrf_requests_are_rejected(app):
    client = app.test_client()
    assert client.get('/api/tokens').status_code == 401
    login(client, app)
    assert client.post('/api/tokens', json={'label': 'test', 'models': ['default']}).status_code == 403
    assert client.post('/api/tokens', json={}, headers={'X-CSRF-Token': 'test-csrf', 'Origin': 'https://evil.test'}).status_code == 403


def test_employee_cannot_access_admin_or_disabled_policy_views(app):
    client = app.test_client()
    headers = login(client, app)
    assert client.get('/api/admin/settings').status_code == 403
    assert client.get('/api/policies').status_code == 403
    assert client.post('/api/admin/settings', json={}, headers=headers).status_code == 403


def test_creation_is_owner_scoped_and_hides_transcripts(app, kube):
    client = app.test_client()
    headers = login(client, app)
    result = client.post('/api/tokens', json={'label': 'Application', 'models': ['default'], 'role': 'admin'}, headers=headers)
    assert result.status_code == 200, result.json
    assert 'trace' not in result.json
    name = result.json['name']
    raw = result.json['raw']
    assert raw not in json.dumps(kube.objects)
    assert client.get('/api/tokens').json['tokens'][0]['name'] == name
    other = app.test_client()
    other_headers = login(other, app, 'employee-2')
    assert other.get('/api/tokens').json['tokens'] == []
    for action in ('delete', 'reveal', 'rotate', 'update', 'test'):
        assert other.post('/api/tokens/' + name + '/' + action, json={}, headers=other_headers).status_code == 404


def test_admin_sees_all_and_feature_toggles_apply_server_side(app, kube):
    employee = app.test_client()
    headers = login(employee, app)
    employee.post('/api/tokens', json={'label': 'Application', 'models': ['default']}, headers=headers)
    admin = app.test_client()
    login(admin, app, 'administrator', ['portal-admins'])
    assert len(admin.get('/api/tokens').json['tokens']) == 1
    cm = kube.objects[core('portal', 'configmaps', 'instance-settings')]
    config = json.loads(cm['data']['settings.json'])
    config['features'].update(userTranscript=True, userPolicies=True)
    cm['data']['settings.json'] = json.dumps(config)
    result = employee.post('/api/tokens', json={'label': 'Second app', 'models': ['default']}, headers=headers)
    assert 'trace' in result.json
    assert employee.get('/api/policies').status_code == 200


def test_bootstrap_is_only_available_before_configuration(app, kube):
    client = app.test_client()
    assert client.post('/api/bootstrap', json={'token': 'b' * 64}).status_code == 403
    cm = kube.objects[core('portal', 'configmaps', 'instance-settings')]
    config = json.loads(cm['data']['settings.json'])
    config['configured'] = False
    cm['data']['settings.json'] = json.dumps(config)
    assert client.post('/api/bootstrap', json={'token': 'wrong'}).status_code == 403
    assert client.post('/api/bootstrap', json={'token': 'b' * 64}).status_code == 200
    assert client.get('/api/session').json['user']['bootstrap'] is True
    assert client.get('/api/tokens').status_code == 409
    config['configured'] = True
    cm['data']['settings.json'] = json.dumps(config)
    assert client.get('/api/admin/settings').status_code == 401


def test_encrypted_values_survive_another_store_instance(app):
    client = app.test_client()
    headers = login(client, app)
    result = client.post('/api/tokens', json={'label': 'Persistent', 'models': ['default']}, headers=headers).json
    from portal.store import Store
    original = app.extensions['portal_store']
    restarted = Store(original.kube, original.ns, original.instance, original.settings, 'e' * 64, ['gateways'])
    assert restarted.load_values(result['name'])[result['generation']] == result['raw']


def test_revocation_does_not_depend_on_decrypting_secret_values(app, kube):
    client = app.test_client()
    headers = login(client, app)
    result = client.post('/api/tokens', json={'label': 'Can revoke', 'models': ['default']}, headers=headers).json
    secret = kube.objects[core('portal', 'secrets', result['name'] + '-values')]
    secret['data'][result['generation']] = 'invalid-ciphertext'
    assert client.post('/api/tokens/' + result['name'] + '/revoke', json={}, headers=headers).status_code == 200
    assert client.post('/api/tokens/' + result['name'] + '/delete', json={}, headers=headers).status_code == 200


def test_gateway_probe_uses_a_model_allowed_by_the_token(app, kube):
    import httpx
    client = app.test_client()
    headers = login(client, app)
    cm = kube.objects[core('portal', 'configmaps', 'instance-settings')]
    config = json.loads(cm['data']['settings.json'])
    config['lifecycle']['models'] = ['default', 'other-model']
    cm['data']['settings.json'] = json.dumps(config)
    result = client.post('/api/tokens', json={'label': 'Model restricted', 'models': ['other-model']}, headers=headers).json

    def respond(request):
        assert json.loads(request.content)['model'] == 'other-model'
        return httpx.Response(200, json={})

    app.extensions['portal_store'].http = httpx.Client(transport=httpx.MockTransport(respond))
    test = client.post('/api/tokens/' + result['name'] + '/test', json={}, headers=headers)
    assert test.status_code == 200
    assert test.json['model'] == 'other-model'


def test_setup_save_persists_branding_and_disables_bootstrap(app, kube, monkeypatch):
    client = app.test_client()
    cm = kube.objects[core('portal', 'configmaps', 'instance-settings')]
    config = json.loads(cm['data']['settings.json'])
    config['configured'] = False
    cm['metadata']['annotations'] = {'meta.helm.sh/release-name': 'portal-release'}
    cm['data']['settings.json'] = json.dumps(config)
    monkeypatch.setattr(app.extensions['identity'], 'discovery', lambda issuer: {})
    monkeypatch.setattr(app.extensions['portal_store'], 'configure_gateway', lambda config: None)
    assert client.post('/api/bootstrap', json={'token': 'b' * 64}).status_code == 200
    csrf = client.get('/api/session').json['csrf']
    config['branding']['company'] = 'Example engineering'
    saved = client.post('/api/admin/settings', json={'settings': config, 'resourceVersion': cm['metadata']['resourceVersion']}, headers={'X-CSRF-Token': csrf})
    assert saved.status_code == 200, saved.json
    assert saved.json['signInRequired'] is True
    public = client.get('/api/session').json
    assert public['configured'] is True and public['user'] is None
    assert public['branding']['company'] == 'Example engineering'
    assert client.post('/api/bootstrap', json={'token': 'b' * 64}).status_code == 403
    assert kube.objects[core('portal', 'configmaps', 'instance-settings')]['metadata']['annotations']['meta.helm.sh/release-name'] == 'portal-release'


@pytest.mark.parametrize('bad', [{'issuer': 12}, {'adminGroups': 'admins'}, {'groupsClaim': []}])
def test_invalid_identity_config_is_rejected(bad):
    config = copy.deepcopy(DEFAULTS)
    config['auth'].update(bad)
    with pytest.raises(Exception):
        validate(config, ['gateways'])


def test_branding_import_rejects_markup_logo_and_unknown_fields():
    with pytest.raises(Exception): validate_profile({'logo': 'data:image/svg+xml,<svg onload=alert(1)>'})
    with pytest.raises(Exception): validate_profile({'clientSecret': 'not-a-profile-field'})
    assert validate_profile({'company': 'Example organisation'})['company'] == 'Example organisation'


def test_settings_cannot_expand_helm_namespace_permissions():
    config = copy.deepcopy(DEFAULTS)
    config['gateway']['namespace'] = 'outside-scope'
    with pytest.raises(Exception): validate(config, ['gateways'])
