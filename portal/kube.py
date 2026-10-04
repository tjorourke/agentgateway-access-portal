"""Small in-cluster Kubernetes client. No cluster-admin kubeconfig or impersonation."""
import contextvars
import json
import os
from pathlib import Path
from urllib.parse import urlencode

import httpx

TRACE = contextvars.ContextVar('trace', default=None)


class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


class Kubernetes:
    def __init__(self):
        self.base = os.getenv('KUBERNETES_API', 'https://kubernetes.default.svc').rstrip('/')
        self.sa = Path('/var/run/secrets/kubernetes.io/serviceaccount')
        proxy = os.getenv('LOCAL_KUBECTL_PROXY', '')
        if proxy:
            if not proxy.startswith(('http://127.0.0.1:', 'http://localhost:')):
                raise RuntimeError('Local development proxy must be loopback.')
            self.base = proxy.rstrip('/')
        self.proxy = bool(proxy)
        self.client = httpx.Client(verify=str(self.sa / 'ca.crt') if not proxy else True, timeout=20)

    def call(self, method, path, body=None, *, missing=False, dry_run=False):
        headers = {'Content-Type': 'application/merge-patch+json' if method == 'PATCH' else 'application/json'}
        if not self.proxy:
            headers['Authorization'] = 'Bearer ' + (self.sa / 'token').read_text().strip()
        if dry_run:
            path += ('&' if '?' in path else '?') + 'dryRun=All'
        try:
            response = self.client.request(method, self.base + path, headers=headers, json=body)
        except httpx.HTTPError as error:
            raise ApiError('Kubernetes API unavailable.', 503) from error
        trace = TRACE.get()
        if trace is not None:
            safe_body = {'redacted': 'credential storage'} if '/secrets' in path else body
            trace.append({'method': method, 'path': path, 'status': response.status_code, 'body': safe_body})
        if response.status_code == 404 and missing:
            return None
        data = response.json() if response.content else {}
        if not response.is_success:
            raise ApiError(data.get('message', 'Kubernetes request failed.'), response.status_code)
        return data

    def get(self, path, missing=False):
        return self.call('GET', path, missing=missing)

    def upsert(self, collection, name, body):
        current = self.get(collection + '/' + name, missing=True)
        if current:
            body.setdefault('metadata', {})['resourceVersion'] = current['metadata']['resourceVersion']
            return self.call('PUT', collection + '/' + name, body)
        return self.call('POST', collection, body)


def core(namespace, resource, name=''):
    return f'/api/v1/namespaces/{namespace}/{resource}' + ('/' + name if name else '')


def tokens(namespace, name=''):
    return f'/apis/accessportal.io/v1alpha1/namespaces/{namespace}/accesstokens' + ('/' + name if name else '')


def selector(**labels):
    return '?' + urlencode({'labelSelector': ','.join(f'{k}={v}' for k, v in labels.items())})
