"""Step 14 - staging HTTPS origin and separate ingest-only backend tests."""
from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from cybersentinel_agent.client import AgentError, send_events, validate_ingest_origin, validate_local_server
from cybersentinel_agent.continuous import ContinuousAgent
from owner_api.ingest_only import create_ingest_app
from owner_api.main import create_app
from scripts.step14_preflight import audit

HOST = 'ingest.cybersentinel.example.org'
DOMAIN_ID = 'a' * 32
KEY = 'csa_' + 'k' * 43


def sample(n=1):
    return {'event_id': f'{n:032d}', 'occurred_at': int(time.time()),
            'source_ref': 'b' * 32, 'method': 'POST', 'path_group': 'login',
            'status_code': 401, 'duration_ms': 3.0, 'request_bytes': 150,
            'response_bytes': 200}


class HTTPSOriginTests(unittest.TestCase):
    def test_loopback_unchanged_without_allowlist(self):
        self.assertEqual(validate_ingest_origin('http://127.0.0.1:8002'), 'http://127.0.0.1:8002')
        self.assertEqual(validate_local_server('http://127.0.0.1:8002'), 'http://127.0.0.1:8002')

    def test_remote_requires_explicit_hostname(self):
        with self.assertRaises(AgentError):
            validate_ingest_origin('https://' + HOST)
        self.assertEqual(validate_ingest_origin('https://' + HOST, HOST), 'https://' + HOST)
        self.assertEqual(validate_ingest_origin('https://' + HOST + ':443/', HOST), 'https://' + HOST)
        self.assertEqual(validate_ingest_origin('https://' + HOST.upper(), HOST), 'https://' + HOST)

    def test_rejects_untrusted_or_insecure_destinations(self):
        bad = [
            'http://' + HOST, 'https://evil.example.org',
            'https://' + HOST + ':8443',
            'https://user:pass@' + HOST,
            'https://' + HOST + '/owner/register',
            'https://' + HOST + '/agent/v1/ingest',
            'https://' + HOST + '?redirect=1',
            'https://' + HOST + '#fragment',
            'https://' + HOST + '@127.0.0.1',
            'http://127.0.0.1:8002@' + HOST,
            'https://localhost', 'http://127.0.0.1:8002/owner',
            'https://192.0.2.99',
        ]
        for candidate in bad:
            with self.subTest(candidate=candidate), self.assertRaises(AgentError):
                validate_ingest_origin(candidate, HOST)

    def test_host_cannot_be_ip_or_local_network_name(self):
        for name in ('127.0.0.1','192.0.2.22','ingest.local','foo.test','intranet.internal'):
            with self.subTest(name=name), self.assertRaises(AgentError):
                validate_ingest_origin('https://' + name, name)

    def test_request_uses_no_proxy_and_rejects_redirects(self):
        captured = {}
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def read(self, n):
                return b'{"accepted": 1, "duplicates": 0, "alerts_updated": 0}'
        class FakeOpener:
            def open(self, req, timeout):
                captured['url'] = req.full_url
                captured['auth'] = req.get_header('Authorization')
                captured['timeout'] = timeout
                return Response()
        def builder(*handlers):
            captured['handlers'] = handlers
            return FakeOpener()
        with patch('cybersentinel_agent.client.request.build_opener', side_effect=builder):
            result = send_events('https://' + HOST, DOMAIN_ID, [sample()], KEY,
                                 allowed_remote_host=HOST)
        self.assertEqual(result['accepted'], 1)
        self.assertEqual(captured['url'], 'https://' + HOST + '/agent/v1/ingest')
        self.assertEqual(captured['auth'], 'Bearer ' + KEY)
        self.assertEqual(captured['timeout'], 5)
        self.assertEqual(captured['handlers'][0].proxies, {})
        self.assertIsNone(captured['handlers'][1].redirect_request(None,None,302,'',None,'https://other.example'))

    def test_continuous_agent_uses_approved_host_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            with self.assertRaises(AgentError):
                ContinuousAgent(p/'logs',p/'state.db',DOMAIN_ID,KEY,server='https://'+HOST)
            a = ContinuousAgent(p/'logs',p/'state-ok.db',DOMAIN_ID,KEY,server='https://'+HOST,
                                allowed_remote_host=HOST)
            self.assertEqual(a.server, 'https://'+HOST)
            a.close()


class IngestOnlyAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / 'owner.sqlite3'
        self.admin = TestClient(create_app(self.db, txt_lookup=lambda name: self.records.get(name, [])))
        self.ingest = TestClient(create_ingest_app(self.db))
        self.records = {}

    def test_sensitive_owner_endpoints_and_docs_absent(self):
        for path in ('/docs', '/openapi.json', '/owner/health', '/owner/domains', '/owner/login', '/owner/register'):
            with self.subTest(path=path):
                self.assertEqual(self.ingest.get(path).status_code, 404)
        self.assertEqual(self.ingest.post('/owner/register', json={'email':'a@example.org','password':'abc'}).status_code, 404)
        self.assertEqual(self.ingest.post('/agent/v1/ingest', json={'domain_id':DOMAIN_ID,'events':[sample()]}).status_code, 401)

    def test_staging_ingest_uses_same_persisted_owners_and_alerts(self):
        reg = self.admin.post('/owner/register', json={'email':'alice@mydomain.org','password':'valid-long-password-1234'})
        self.assertEqual(reg.status_code, 201)
        login = self.admin.post('/owner/login',json={'email':'alice@mydomain.org','password':'valid-long-password-1234'})
        auth = {'Authorization': 'Bearer ' + login.json()['access_token']}
        added = self.admin.post('/owner/domains', headers=auth, json={'domain':'alice-domain.org'}).json()
        self.records[added['txt_name']] = [added['txt_value']]
        self.assertEqual(self.admin.post('/owner/domains/'+added['id']+'/verify', headers=auth).status_code, 200)
        key = self.admin.post('/owner/domains/'+added['id']+'/agent-keys',headers=auth,json={'label':'staging'}).json()['agent_key']
        events = [sample(n) for n in range(5)]
        body = {'domain_id':added['id'],'events':events}
        head = {'Authorization':'Bearer '+key}
        resp = self.ingest.post('/agent/v1/ingest', headers=head, json=body)
        self.assertEqual(resp.status_code, 200,resp.text)
        self.assertEqual(resp.json()['accepted'],5)
        self.assertEqual(self.ingest.post('/agent/v1/ingest', headers=head, json=body).json()['duplicates'],5)
        alerts = self.admin.get('/owner/domains/'+added['id']+'/alerts',headers=auth)
        self.assertEqual(alerts.status_code,200)
        self.assertEqual(alerts.json()['total_alerts'],1)

    def test_ingest_only_disallows_non_loopback_clients(self):
        remote=TestClient(create_ingest_app(self.db),client=('192.0.2.5',4242))
        self.assertEqual(remote.post('/agent/v1/ingest',json={'domain_id':DOMAIN_ID,'events':[sample()]}).status_code,403)

    def test_staging_body_size_limit(self):
        self.assertEqual(self.ingest.post('/agent/v1/ingest',content=b'a'*40000).status_code,413)

    def test_no_owner_routes_in_ingest_openapi(self):
        paths = set(self.ingest.app.routes[i].path for i in range(len(self.ingest.app.routes)))
        self.assertEqual(paths, {'/agent/v1/ingest'})


class TemplateTests(unittest.TestCase):
    def test_checked_in_templates_are_fail_closed(self):
        report = audit(Path(__file__).resolve().parents[1])
        self.assertEqual(report['status'],'pass',report)

    def test_templates_bind_only_loopback_backends(self):
        root=Path(__file__).resolve().parents[1]
        caddy=(root/'deploy/Caddyfile.ingest.example').read_text()
        self.assertNotIn('reverse_proxy 0.0.0.0',caddy)
        self.assertNotIn('reverse_proxy 127.0.0.1:8002',caddy)
        self.assertIn('respond "Not found" 404',caddy)


if __name__=='__main__':
    unittest.main()
