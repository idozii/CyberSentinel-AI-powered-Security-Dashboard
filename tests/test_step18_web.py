"""Private owner portal operations must inherit browser session and CSRF safeguards."""
from __future__ import annotations

import unittest
import uuid

from fastapi.testclient import TestClient

from hosted_api.identity import Identity
from hosted_api.settings import HostedSettings
from hosted_api.web import create_web_app
from hosted_api.web_auth import MemorySessions, WebSettings


class StubBrowserStore:
    def __init__(self, did):
        self.did = did
    def ensure_identity(self, subject):
        return {'id':str(uuid.uuid4())}
    def list_domains(self, subject):
        return [{'id':str(self.did),'domain':'staging-example.org','verified':True}]


class StubMonitoring:
    def __init__(self):
        self.did = None
        self.issued = []
        self.revoked = []
        self.acked = []
    def list_keys(self, subject, did):
        return []
    def recent(self, subject, did, limit=20):
        return {'total_events':0, 'events':[]}
    def list_alerts(self, subject, did, limit=20):
        return {'total_alerts':0, 'alerts':[]}
    def issue_key(self, subject, did, label):
        self.issued.append((subject.subject,did,label))
        return {'agent_key':'csp_safe_fake_value','id':str(uuid.uuid4())}
    def revoke_key(self, subject, did, key_id):
        self.revoked.append((subject.subject,did,key_id))
    def acknowledge(self, subject, did, alert_id):
        self.acked.append((subject.subject,did,alert_id))


class FakeExchange:
    def authorize_url(self, state, pending):
        return 'https://auth.example.org/authorize?state='+state
    def exchange(self, code, pending):
        return Identity('https://auth.example.org/','test-owner')


class Step18BrowserTest(unittest.TestCase):
    def setUp(self):
        settings = WebSettings.validate(
            HostedSettings.validate('https://auth.example.org/','api-id',
                                    'https://auth.example.org/.well-known/jwks.json',
                                    'postgresql://not-used'),
            'dummy-client-id','dummy-long-client-secret','http://127.0.0.1:8007/auth/callback')
        self.domain = uuid.uuid4()
        self.ops = StubMonitoring()
        self.sessions = MemorySessions()
        self.app = create_web_app(settings,store=StubBrowserStore(self.domain),
                                  sessions=self.sessions,monitoring=self.ops,exchanger=FakeExchange())
        self.client = TestClient(self.app,follow_redirects=False)

    def login(self):
        start = self.client.get('/auth/login')
        from urllib.parse import parse_qs, urlsplit
        state = parse_qs(urlsplit(start.headers['location']).query)['state'][0]
        resp = self.client.get('/auth/callback',params={'code':'fake','state':state})
        self.assertEqual(resp.status_code,303)
        return next(iter(self.sessions.sessions.values())).csrf

    def test_monitoring_routes_require_authenticated_browser_session(self):
        url=f'/domains/{self.domain}/monitor'
        self.assertEqual(self.client.get(url).status_code,401)
        self.assertEqual(self.client.post(f'/domains/{self.domain}/keys',data={'label':'agent'}).status_code,401)
        self.login()
        r=self.client.get(url)
        self.assertEqual(r.status_code,200)
        self.assertIn('Private test endpoint',r.text)
        self.assertIn('Manage monitoring',self.client.get('/domains').text)

    def test_csrf_required_for_key_and_alert_changes(self):
        csrf=self.login()
        base=f'/domains/{self.domain}'
        self.assertEqual(self.client.post(base+'/keys',data={'label':'nginx'}).status_code,403)
        self.assertEqual(self.ops.issued,[])
        posted=self.client.post(base+'/keys',data={'label':'nginx','_csrf':csrf})
        self.assertEqual(posted.status_code,200)
        self.assertIn('csp_safe_fake_value',posted.text)
        self.assertEqual(len(self.ops.issued),1)
        kid=uuid.uuid4()
        self.assertEqual(self.client.post(base+f'/keys/{kid}/revoke',data={'_csrf':'wrong'}).status_code,403)
        self.assertEqual(self.client.post(base+f'/keys/{kid}/revoke',data={'_csrf':csrf}).status_code,303)
        aid=uuid.uuid4()
        self.assertEqual(self.client.post(base+f'/alerts/{aid}/acknowledge',data={'_csrf':'wrong'}).status_code,403)
        self.assertEqual(self.client.post(base+f'/alerts/{aid}/acknowledge',data={'_csrf':csrf}).status_code,303)
        self.assertEqual(len(self.ops.revoked),1)
        self.assertEqual(len(self.ops.acked),1)


if __name__ == '__main__':
    unittest.main()
