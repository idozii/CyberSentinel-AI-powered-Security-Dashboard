"""Private Auth0 browser BFF tests. No live Auth0 or Neon credentials required."""
from __future__ import annotations

import re
import time
import unittest
import uuid
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from hosted_api.identity import Identity, OIDCVerifier
from hosted_api.postgres import HostedError
from hosted_api.settings import HostedSettings
from hosted_api.web import create_web_app
from hosted_api.web_auth import (Auth0CodeExchange, COOKIE, FLOW_COOKIE, MemorySessions,
                                  WebLoginError, WebSettings, challenge)

CFG = WebSettings.validate(
    HostedSettings.validate('https://cybersentinel.au.auth0.com/',
                            'https://cybersentinel.example/api',
                            'https://cybersentinel.au.auth0.com/.well-known/jwks.json',
                            'postgresql://not-used'),
    'auth0ClientId12345', 'sample-secret-with-minimum-length',
    'http://127.0.0.1:8007/auth/callback')


class DummyStore:
    def __init__(self):
        self.accounts = set()
        self.domains = {}
        self.added = []
    def ensure_identity(self, user):
        self.accounts.add(user.subject)
    def list_domains(self, user):
        return self.domains.get(user.subject, [])
    def create_domain(self, user, domain):
        self.added.append((user.subject, domain))
        return {'id': uuid.uuid4().hex, 'domain': domain, 'verified':False,
                'txt_name':'_cybersentinel-verify.'+domain,
                'txt_value':'cybersentinel-verification=sample'}
    def verify_domain(self, user, did, lookup):
        return {'domain':'example.org','verified':True}


class StubExchange:
    def __init__(self):
        self.authorizations = []
        self.calls = []
        self.user = Identity(CFG.hosted.issuer, 'owner-alice')
    def authorize_url(self, state, pending):
        self.authorizations.append((state,pending))
        return 'https://cybersentinel.au.auth0.com/authorize?state='+state+'&code_challenge='+challenge(pending.verifier)
    def exchange(self, code, pending):
        self.calls.append((code,pending))
        return self.user


class WebUI(unittest.TestCase):
    def setUp(self):
        self.exchange = StubExchange()
        self.store = DummyStore()
        self.sessions = MemorySessions()
        self.app = create_web_app(CFG, exchanger=self.exchange,
                                  store=self.store, sessions=self.sessions,
                                  dns_lookup=lambda name: [])
        self.client = TestClient(self.app,follow_redirects=False)

    def initiate(self):
        r=self.client.get('/auth/login')
        self.assertEqual(r.status_code,302)
        self.assertEqual(len(self.exchange.authorizations),1)
        self.assertIn('HttpOnly',r.headers['set-cookie'])
        self.assertIn('SameSite=lax',r.headers['set-cookie'])
        self.assertNotIn('client_secret',r.headers['location'])
        self.assertIn('code_challenge=',r.headers['location'])
        return self.exchange.authorizations[-1][0]

    def login(self):
        state=self.initiate()
        r=self.client.get('/auth/callback',params={'state':state,'code':'signed-code'})
        self.assertEqual(r.status_code,303,r.text)
        self.assertEqual(r.headers['location'],'/domains')
        return r

    def csrf(self):
        return next(iter(self.sessions.sessions.values())).csrf

    def test_home_requires_login_and_no_public_api_docs(self):
        r=self.client.get('/')
        self.assertIn('Sign in with Auth0',r.text)
        self.assertEqual(self.client.get('/domains').status_code,401)
        self.assertEqual(self.client.get('/docs').status_code,404)
        self.assertEqual(self.client.get('/openapi.json').status_code,404)

    def test_browser_binding_required_and_state_one_time(self):
        s=self.initiate()
        self.client.cookies.pop(FLOW_COOKIE)
        self.assertEqual(self.client.get('/auth/callback',params={'code':'ok','state':s}).status_code,400)
        self.assertEqual(self.client.get('/auth/callback',params={'code':'ok','state':s}).status_code,400)
        self.assertEqual(self.exchange.calls,[])

    def test_valid_flow_private_cookie_no_token_in_browser(self):
        r=self.login()
        self.assertIn(COOKIE, self.client.cookies)
        self.assertNotIn('signed-code',r.headers.get('set-cookie',''))
        self.assertNotIn('owner-alice',r.headers.get('set-cookie',''))
        self.assertIn('HttpOnly',r.headers['set-cookie'])
        self.assertIn('no-store',r.headers['cache-control'])
        self.assertIn('no-referrer',r.headers['referrer-policy'])
        self.assertIn('DENY',r.headers['x-frame-options'])
        self.assertIn('owner-alice',self.store.accounts)
        self.assertEqual(self.client.get('/domains').status_code,200)

    def test_auth_state_replay_and_invalid_code(self):
        self.login()
        s=self.exchange.authorizations[-1][0]
        self.assertEqual(self.client.get('/auth/callback',params={'state':s,'code':'ok'}).status_code,400)

    def test_malformed_callback_parameters(self):
        self.initiate()
        self.assertEqual(self.client.get('/auth/callback?state=abc&state=def&code=c').status_code,422)

    def test_post_requires_csrf_and_form_encoding(self):
        self.login()
        self.assertEqual(self.client.post('/domains/add',data={'domain':'domain.org'}).status_code,403)
        self.assertEqual(self.client.post('/domains/add',data={'_csrf':'bad','domain':'domain.org'}).status_code,403)
        self.assertEqual(self.client.post('/domains/add',json={'_csrf':self.csrf(),'domain':'domain.org'}).status_code,415)
        self.assertEqual(self.store.added,[])
        self.assertEqual(self.client.post('/domains/add',data={'_csrf':self.csrf(),'domain':'domain.org'}).status_code,200)
        self.assertEqual(self.store.added,[('owner-alice','domain.org')])

    def test_duplicate_form_values_rejected(self):
        self.login()
        r=self.client.post('/domains/add',content='domain=a.org&domain=b.org&_csrf='+self.csrf(),
                           headers={'Content-Type':'application/x-www-form-urlencoded'})
        self.assertEqual(r.status_code,422)

    def test_domain_value_escaped(self):
        self.login()
        self.store.domains['owner-alice']=[{'domain':'<script>alert(1)</script>','verified':True,'id':uuid.uuid4().hex}]
        page=self.client.get('/domains').text
        self.assertNotIn('<script>',page)
        self.assertIn('&lt;script&gt;',page)

    def test_logout_csrf_and_revocation(self):
        self.login()
        self.assertEqual(self.client.post('/auth/logout',data={'_csrf':'bad'}).status_code,403)
        r=self.client.post('/auth/logout',data={'_csrf':self.csrf()})
        self.assertEqual(r.status_code,303)
        self.assertEqual(self.client.get('/domains').status_code,401)

    def test_untrusted_host_and_remote_address(self):
        self.assertEqual(self.client.get('/health',headers={'Host':'bad.example'}).status_code,400)
        outside=TestClient(self.app, client=('192.0.2.4',3200))
        self.assertEqual(outside.get('/health').status_code,403)

    def test_forged_cookie_and_login_not_public(self):
        self.client.cookies.set(COOKIE,'x'*60)
        self.assertEqual(self.client.get('/domains').status_code,401)
        h=self.client.get('/health').json()
        self.assertFalse(h['public_signup'])
        self.assertFalse(h['telemetry_postgres_migrated'])


class SessionSafety(unittest.TestCase):
    def test_expiration_and_replay(self):
        clock=[1000.0]
        cache=MemorySessions(clock=lambda: clock[0])
        state, flow, pending=cache.begin()
        self.assertEqual(cache.consume(state,flow),pending)
        with self.assertRaises(WebLoginError):cache.consume(state,flow)
        ticket=cache.issue(Identity('https://issuer/', 'a'), lifetime=10)
        self.assertIsNotNone(cache.get(ticket))
        clock[0]=1011.0
        self.assertIsNone(cache.get(ticket))
        s,f,_=cache.begin()
        clock[0]=1312.0
        with self.assertRaises(WebLoginError):cache.consume(s,f)

    def test_config_rejects_public_callback_and_provider_mix(self):
        for callback in ['https://cybersentinel.example/auth/callback',
                         'http://localhost:8007/auth/callback',
                         'http://127.0.0.1:8006/auth/callback']:
            with self.subTest(callback=callback),self.assertRaises(ValueError):
                WebSettings.validate(CFG.hosted, CFG.client_id, CFG.client_secret, callback)
        wrong=HostedSettings.validate(CFG.hosted.issuer,CFG.hosted.audience,
                    'https://elsewhere.example/.well-known/jwks.json',CFG.hosted.runtime_dsn)
        with self.assertRaises(ValueError):
            WebSettings.validate(wrong, CFG.client_id, CFG.client_secret, CFG.callback_url)


class FakeJWKS:
    def __init__(self,key):self.key=key
    def get_signing_key_from_jwt(self, token):
        from types import SimpleNamespace
        return SimpleNamespace(key=self.key.public_key(),algorithm_name='RS256')

class FakeAuth0HTTP:
    def __init__(self, response):
        self.response=response
        self.calls=[]
    def post(self,url,data):
        self.calls.append((url,data))
        return self.response

class CodeExchangeTests(unittest.TestCase):
    def setUp(self):
        self.private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        self.keys=FakeJWKS(self.private)
        self.verifier=OIDCVerifier(CFG.hosted,jwks_client=self.keys)
        self.sessions=MemorySessions()
        _,_,self.pending=self.sessions.begin()

    def token(self,audience,nonce=None,subject='alice'):
        now=int(time.time())
        claims={'iss':CFG.hosted.issuer,'aud':audience,'sub':subject,'iat':now,'exp':now+120}
        if nonce is not None:claims['nonce']=nonce
        return jwt.encode(claims,self.private,algorithm='RS256',headers={'kid':'k1'})

    def exchange(self,nonce=None,id_sub='alice'):
        data={'access_token':self.token(CFG.hosted.audience),
              'id_token':self.token(CFG.client_id,nonce if nonce is not None else self.pending.nonce,subject=id_sub),
              'token_type':'Bearer'}
        client=FakeAuth0HTTP(httpx.Response(200,json=data))
        out=Auth0CodeExchange(CFG,verifier=self.verifier,jwks=self.keys,client=client)
        return out,client

    def test_authorization_url_pkce_and_confidential_exchange(self):
        ex,client=self.exchange()
        url=ex.authorize_url('stateABC',self.pending)
        args=parse_qs(urlsplit(url).query)
        self.assertEqual(args['code_challenge_method'],['S256'])
        self.assertEqual(args['nonce'],[self.pending.nonce])
        self.assertEqual(args['audience'],[CFG.hosted.audience])
        self.assertNotIn('client_secret',url)
        got=ex.exchange('authorization-code',self.pending)
        self.assertEqual(got.subject,'alice')
        self.assertEqual(client.calls[0][1]['code_verifier'],self.pending.verifier)
        self.assertEqual(client.calls[0][1]['client_secret'],CFG.client_secret)

    def test_wrong_id_nonce_rejected(self):
        ex,_=self.exchange(nonce='WRONG')
        with self.assertRaises(WebLoginError):ex.exchange('code',self.pending)

    def test_wrong_id_subject_rejected(self):
        ex,_=self.exchange(id_sub='mallory')
        with self.assertRaises(WebLoginError):ex.exchange('code',self.pending)

    def test_wrong_api_audience_rejected(self):
        ex,client=self.exchange()
        payload=client.response.json()
        payload['access_token']=self.token('https://wrong-audience')
        client.response=httpx.Response(200,json=payload)
        with self.assertRaises(WebLoginError):ex.exchange('code',self.pending)

    def test_upstream_error_rejected_without_token_echo(self):
        ex,client=self.exchange()
        client.response=httpx.Response(401,json={'error':'not_authorized'})
        with self.assertRaisesRegex(WebLoginError,'rejected'):
            ex.exchange('code',self.pending)

if __name__=='__main__':unittest.main()
