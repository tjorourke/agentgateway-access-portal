"""Explicit local integration-test fixtures. Not installed by the application chart."""
import argparse
import json
import hashlib
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--context', required=True)
parser.add_argument('--namespace', default='access-portal')
parser.add_argument('--image', default='localhost:5001/agentgateway-access-portal:dev')
parser.add_argument('--gateway-namespace', default='agentgateway-system')
parser.add_argument('--gateway-class', default='enterprise-agentgateway')
args = parser.parse_args()
K = ['kubectl','--context',args.context]
ROOT = Path(__file__).parent
docs = []
for component, port, source in [('oidc',8090,'oidc_provider.py'),('model',8000,'model_fixture.py')]:
    name = 'access-portal-test-'+component
    docs.append({'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':name,'namespace':args.namespace},'data':{'server.py':(ROOT/source).read_text()}})
    docs.append({'apiVersion':'apps/v1','kind':'Deployment','metadata':{'name':name,'namespace':args.namespace},'spec':{
        'replicas':1,'selector':{'matchLabels':{'app':name}},'template':{'metadata':{'labels':{'app':name}, 'annotations':{'fixture-source': hashlib.sha256((ROOT/source).read_bytes()).hexdigest()}},'spec':{
            'automountServiceAccountToken':False,'containers':[{'name':'fixture','image':args.image,'command':['python','/fixture/server.py'],
                'ports':[{'containerPort':port}], 'resources':{'requests':{'cpu':'10m','memory':'40Mi'},'limits':{'memory':'128Mi'}},
                'volumeMounts':[{'name':'source','mountPath':'/fixture'}]}],'volumes':[{'name':'source','configMap':{'name':name}}]}}}})
    docs.append({'apiVersion':'v1','kind':'Service','metadata':{'name':name,'namespace':args.namespace},'spec':{
        'type':'LoadBalancer' if component=='oidc' else 'ClusterIP','selector':{'app':name},'ports':[{'port':port,'targetPort':port}]}})
docs += [
    {'apiVersion':'gateway.networking.k8s.io/v1','kind':'Gateway','metadata':{'name':'access-portal-test','namespace':args.gateway_namespace},
     'spec':{'gatewayClassName':args.gateway_class,'listeners':[{'name':'http','protocol':'HTTP','port':8080,'allowedRoutes':{'namespaces':{'from':'Same'}}}]}},
    {'apiVersion':'enterpriseagentgateway.solo.io/v1alpha1','kind':'EnterpriseAgentgatewayBackend',
     'metadata':{'name':'access-portal-test-model','namespace':args.gateway_namespace},
     'spec':{'ai':{'provider':{'openai':{},'host':f'access-portal-test-model.{args.namespace}.svc.cluster.local','port':8000}}}},
    {'apiVersion':'gateway.networking.k8s.io/v1','kind':'HTTPRoute','metadata':{'name':'access-portal-test','namespace':args.gateway_namespace},
     'spec':{'parentRefs':[{'name':'access-portal-test'}],'rules':[{'backendRefs':[{'group':'enterpriseagentgateway.solo.io','kind':'EnterpriseAgentgatewayBackend','name':'access-portal-test-model'}]}]}},
]
subprocess.run(K+['apply','-f','-'],input=json.dumps({'apiVersion':'v1','kind':'List','items':docs}),text=True,check=True)
for name in ('access-portal-test-oidc','access-portal-test-model'):
    subprocess.run(K+['-n',args.namespace,'rollout','status','deployment/'+name,'--timeout=120s'],check=True)
subprocess.run(K+['-n',args.namespace,'get','service','access-portal-test-oidc'],check=True)
