import functools
import json
import os
import secrets
import time

import yaml
from flask import Flask, g, jsonify, make_response, redirect, render_template, request

from .config import Settings, validate, validate_profile
from .identity import Identity, principal
from .kube import ApiError, Kubernetes, TRACE, core, selector, tokens
from .store import Store, current


def create_app(kube=None, overrides=None):
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=262144, TESTING=False)
    if overrides:
        app.config.update(overrides)
    env = lambda key, default='': app.config.get(key, os.getenv(key, default))
    namespace, instance = env('PORTAL_NAMESPACE', 'access-portal'), env('PORTAL_INSTANCE', 'access-portal')
    allowed = [s.strip() for s in env('GATEWAY_NAMESPACES', 'agentgateway-system').split(',') if s.strip()]
    public_url = env('PUBLIC_URL', 'http://localhost:8080').rstrip('/')
    secure_cookie = public_url.startswith('https://')
    api = kube or Kubernetes()
    settings = Settings(api, namespace, instance + '-settings')
    identity = Identity(env('SESSION_KEY'), public_url, env('OIDC_CLIENT_SECRET'), int(env('SESSION_SECONDS', '3600')))
    store = Store(api, namespace, instance, settings, env('TOKEN_ENCRYPTION_KEY'), allowed,
                  env('MANAGE_GATEWAY_POLICY', 'true') == 'true', env('ENTERPRISE_BUDGETS', 'true') == 'true')
    app.extensions.update(identity=identity, portal_store=store, portal_settings=settings)

    def cookie(response, name, value, max_age):
        response.set_cookie(name, value, max_age=max_age, secure=secure_cookie, httponly=True, samesite='Lax', path='/')
        return response

    def authenticate():
        config, version = settings.read()
        g.settings, g.settings_version = config, version
        session = identity.open(request.cookies.get('portal_session', ''), identity.session_seconds)
        g.session, g.who = session, None
        if session:
            if session.get('bootstrap') and not config['configured']:
                g.who = {'id': 'bootstrap', 'name': 'Installation administrator', 'role': 'admin', 'bootstrap': True}
            elif session.get('claims'):
                if session['claims'].get('iss') != config['auth']['issuer']:
                    g.session = None
                    return
                g.who = principal(session['claims'], config)

    def protected(admin=False, configured=True):
        def decorate(fn):
            @functools.wraps(fn)
            def wrapped(*args, **kwargs):
                authenticate()
                if not g.who:
                    raise ApiError('Sign in to continue.', 401)
                if admin and g.who['role'] != 'admin':
                    raise ApiError('Administrator access required.', 403)
                if configured and not g.settings['configured']:
                    raise ApiError('Complete installation settings first.', 409)
                if request.method not in ('GET', 'HEAD'):
                    supplied = request.headers.get('X-CSRF-Token', '')
                    if not supplied or not secrets.compare_digest(supplied, g.session['csrf']):
                        raise ApiError('Invalid CSRF token.', 403)
                return fn(*args, **kwargs)
            return wrapped
        return decorate

    @app.before_request
    def before():
        g.trace_reset = TRACE.set([])
        if request.method not in ('GET', 'HEAD', 'OPTIONS'):
            origin = request.headers.get('Origin')
            if origin and origin != public_url:
                raise ApiError('Cross-origin request rejected.', 403)

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        if secure_cookie:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        if hasattr(g, 'trace_reset'):
            TRACE.reset(g.trace_reset)
        return response

    @app.errorhandler(ApiError)
    def error(exc):
        return jsonify(ok=False, error=str(exc)), exc.status if 400 <= exc.status < 600 else 400

    @app.errorhandler(413)
    def too_large(exc):
        return jsonify(ok=False, error='Upload/request too large.'), 413

    def body():
        value = request.get_json(silent=True)
        if not isinstance(value, dict):
            raise ApiError('Expected a JSON object.')
        return value

    def result(**values):
        if g.who['role'] == 'admin' or g.settings['features']['userTranscript']:
            values['trace'] = TRACE.get()
        return jsonify(ok=True, **values)

    @app.get('/healthz')
    def health():
        return jsonify(ok=True)

    @app.get('/readyz')
    def ready():
        settings.read()
        return jsonify(ok=True)

    @app.get('/')
    @app.get('/keys')
    @app.get('/admin')
    def page():
        return render_template('index.html')

    @app.get('/api/session')
    def session():
        authenticate()
        return jsonify(ok=True, configured=g.settings['configured'], branding=g.settings['branding'],
                       user=g.who, csrf=g.session['csrf'] if g.who else '',
                       features=g.settings['features'] if g.who else {},
                       clientSecretConfigured=bool(identity.client_secret) if g.who and g.who['role'] == 'admin' else None)

    @app.post('/api/bootstrap')
    def bootstrap():
        config, _ = settings.read()
        supplied = str(body().get('token', ''))
        expected = env('BOOTSTRAP_TOKEN')
        if config['configured'] or not expected or not secrets.compare_digest(supplied, expected):
            raise ApiError('Invalid bootstrap credential or installation already configured.', 403)
        response = jsonify(ok=True)
        return cookie(response, 'portal_session', identity.seal({'bootstrap': True, 'csrf': secrets.token_urlsafe(24),
                      'expires': time.time() + 900}), 900)

    @app.get('/auth/login')
    def login():
        config, _ = settings.read()
        if not config['configured']:
            return redirect('/admin')
        url, transaction = identity.start(config)
        return cookie(redirect(url), 'portal_oidc', transaction, 300)

    @app.get('/auth/callback')
    def callback():
        config, _ = settings.read()
        value = identity.finish(config, request.cookies.get('portal_oidc', ''), request.args.get('state'), request.args.get('code'))
        response = cookie(redirect('/keys'), 'portal_session', value, identity.session_seconds)
        response.delete_cookie('portal_oidc', path='/')
        return response

    @app.post('/api/logout')
    @protected(configured=False)
    def logout():
        response = jsonify(ok=True)
        response.delete_cookie('portal_session', path='/')
        return response

    @app.get('/api/admin/settings')
    @protected(admin=True, configured=False)
    def get_settings():
        return jsonify(ok=True, settings=g.settings, resourceVersion=g.settings_version,
                       namespaces=allowed, permissions=store.permissions(), reconciler=env('RECONCILER_MODE', 'kyverno'),
                       manageGatewayPolicy=store.manage_gateway)

    @app.get('/api/admin/gateways')
    @protected(admin=True, configured=False)
    def gateways():
        return jsonify(ok=True, gateways=store.discover())

    @app.post('/api/admin/profile')
    @protected(admin=True, configured=False)
    def profile():
        return jsonify(ok=True, branding=validate_profile(body()))

    @app.post('/api/admin/settings')
    @protected(admin=True, configured=False)
    def save_settings():
        data = body()
        if data.get('resourceVersion') != g.settings_version:
            raise ApiError('Settings changed. Reload before saving.', 409)
        config = validate(data.get('settings', {}), allowed, env('ALLOW_INSECURE_OIDC', 'false') == 'true')
        config['configured'] = True
        config = validate(config, allowed, env('ALLOW_INSECURE_OIDC', 'false') == 'true')
        identity.discovery(config['auth']['issuer'])
        gateway_changed = any(config['gateway'][key] != g.settings['gateway'][key] for key in ('namespace', 'name', 'edition'))
        if g.settings['configured'] and gateway_changed and any(o['spec']['status'] == 'active' for o in store.list(g.who)):
            raise ApiError('Revoke or migrate active tokens before changing the gateway connection.', 409)
        if not g.who.get('bootstrap'):
            # Reject a role mapping that removes the administrator performing the change.
            if principal(g.session['claims'], config)['role'] != 'admin':
                raise ApiError('These mappings would remove your administrator access.', 409)
        store.configure_gateway(config)
        saved = settings.write(config, g.settings_version)
        # Changing rotation settings updates desired deadlines, never expiry dates.
        for obj in store.list({'id': '', 'role': 'admin'}):
            if obj['spec']['status'] == 'active':
                store.schedule(obj['spec'], config)
                store.save(obj, wait=False)
        response = result(resourceVersion=saved['metadata']['resourceVersion'], signInRequired=bool(g.who.get('bootstrap')))
        if g.who.get('bootstrap'):
            response.delete_cookie('portal_session', path='/')
        return response

    @app.get('/api/tokens')
    @protected()
    def inventory():
        rows = []
        for obj in store.list(g.who):
            spec = obj['spec']
            rows.append({'name': obj['metadata']['name'], **{key: value for key, value in spec.items() if key not in ('generations', 'standby')},
                         'generations': [{key: value for key, value in gen.items() if key != 'entry'} for gen in spec['generations']]})
        rows.sort(key=lambda r: r['createdAt'], reverse=True)
        return jsonify(ok=True, tokens=rows, models=g.settings['lifecycle']['models'],
                       defaultExpiryMinutes=g.settings['lifecycle']['defaultExpiryMinutes'])

    @app.post('/api/tokens')
    @protected()
    def create_token():
        return result(**store.create(g.who, body(), g.settings))

    @app.post('/api/tokens/<name>/<action>')
    @protected()
    def token_action(name, action):
        return result(**store.action(g.who, name, action, body(), g.settings))

    @app.post('/api/bulk')
    @protected()
    def bulk():
        data = body()
        names, action = data.get('names'), data.get('action')
        if not isinstance(names, list) or not 1 <= len(names) <= 25 or not all(isinstance(n, str) for n in names):
            raise ApiError('Select between 1 and 25 tokens.')
        if action not in ('delete', 'revoke'):
            raise ApiError('Choose delete or revoke.')
        results = []
        for name in dict.fromkeys(names):
            try:
                store.action(g.who, name, action, {}, g.settings)
                results.append({'name': name, 'ok': True})
            except ApiError as exc:
                results.append({'name': name, 'ok': False, 'error': str(exc)})
        return result(results=results)

    @app.get('/api/activity')
    @protected()
    def activity():
        events = api.get(core(namespace, 'events') + selector(**store.labels(g.who['id'] if g.who['role'] != 'admin' else None))).get('items', [])
        return jsonify(ok=True, events=sorted([{'time': e.get('lastTimestamp') or e['metadata']['creationTimestamp'],
            'reason': e.get('reason'), 'message': e.get('message'), 'token': e['metadata'].get('labels', {}).get('accessportal.io/token')}
            for e in events], key=lambda e: e['time'], reverse=True)[:100])

    @app.get('/api/policies')
    @protected()
    def policies():
        if g.who['role'] != 'admin' and not g.settings['features']['userPolicies']:
            raise ApiError('Policy visibility is disabled for employees.', 403)
        if env('RECONCILER_MODE', 'kyverno') != 'kyverno':
            return jsonify(ok=True, mode='external', policies=[])
        rows = []
        refs = [('generatingpolicies', 'publish'), ('mutatingpolicies', 'hashes'), ('mutatingpolicies', 'expire'),
                ('mutatingpolicies', 'rotate'), ('generatingpolicies', 'events'), ('validatingpolicies', 'ownership')]
        if store.enterprise_budgets:
            refs += [('generatingpolicies', 'budgets'), ('mutatingpolicies', 'budget-settings')]
        for plural, suffix in refs:
            obj = api.get('/apis/policies.kyverno.io/v1/' + plural + '/' + instance + '-' + suffix, missing=True)
            if not obj:
                rows.append({'name': instance + '-' + suffix, 'kind': plural, 'ready': False, 'yaml': '# Policy is not installed.'})
                continue
            status = obj.get('status', {}).get('conditionStatus', {})
            rows.append({'name': obj['metadata']['name'], 'kind': obj['kind'], 'ready': status.get('ready', False),
                         'yaml': yaml.safe_dump({'apiVersion': obj['apiVersion'], 'kind': obj['kind'],
                               'metadata': {'name': obj['metadata']['name']}, 'spec': obj['spec']}, sort_keys=False)})
        return jsonify(ok=True, mode='kyverno', policies=rows)

    return app
