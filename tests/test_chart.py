from pathlib import Path
import subprocess

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / 'charts' / 'agentgateway-access-portal'


def render(*options):
    result = subprocess.run(['helm', 'template', 'test', str(CHART), '--namespace', 'portal-test', '--include-crds', *options],
                            text=True, capture_output=True, check=True)
    return [d for d in yaml.safe_load_all(result.stdout) if d]


def test_default_uses_existing_kyverno_and_policies_are_shipped():
    docs = render()
    deployments = [d for d in docs if d['kind'] == 'Deployment']
    assert len(deployments) == 1
    bundle = next(d for d in docs if d['kind'] == 'ConfigMap' and d['metadata']['name'].endswith('-policy-bundle'))
    policies = list(yaml.safe_load_all(bundle['data']['policies.yaml']))
    assert len(policies) == 8
    assert all(p['apiVersion'] == 'policies.kyverno.io/v1' for p in policies)
    assert any(d['kind'] == 'CronJob' for d in docs)
    assert not any(d['kind'] == 'Secret' and 'demo' in d['metadata']['name'] for d in docs)


def test_external_mode_has_no_kyverno_policies_hooks_or_clock():
    docs = render('--set', 'policies.enabled=false')
    assert not any(d['kind'] in ('Job', 'CronJob') for d in docs)
    assert not any(d['kind'] == 'ConfigMap' and 'policies.yaml' in d.get('data', {}) for d in docs)
    assert len([d for d in docs if d['kind'] == 'Deployment']) == 1


def test_optional_engine_is_pinned_and_separate_from_portal_namespace():
    docs = render('--set', 'kyverno.enabled=true')
    controllers = [d for d in docs if d['kind'] == 'Deployment' and d['metadata'].get('namespace') == 'kyverno']
    assert len(controllers) >= 3
    for dep in controllers:
        assert dep['spec']['template']['spec']['containers'][0]['image'].endswith(':v1.19.0')


def test_oss_mode_omits_enterprise_budget_policies():
    docs = render('--set', 'enterpriseBudgets.enabled=false')
    bundle = next(d for d in docs if d['kind'] == 'ConfigMap' and d['metadata']['name'].endswith('-policy-bundle'))
    assert len(list(yaml.safe_load_all(bundle['data']['policies.yaml']))) == 6
