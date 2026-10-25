"""Step 31-32: SOC UI regression, no external requests and fail-closed beta gate."""
from __future__ import annotations

import time
import unittest
import uuid

from fastapi.testclient import TestClient

from hosted_api.local_demo import DemoStore, create_demo_app


class SocUiTest(unittest.TestCase):
    def setUp(self):
        self.store = DemoStore()
        self.client = TestClient(create_demo_app(self.store, enabled=True))
        self.key = self.store.issue_key()

    def tearDown(self):
        self.client.close()

    @staticmethod
    def events(n=5, *, status=401, group='login', source=None, when=None):
        src = source or uuid.uuid4().hex
        return [dict(event_id=uuid.uuid4().hex, occurred_at=when or int(time.time()),
                     source_ref=src, method='GET', path_group=group, status_code=status,
                     duration_ms=1.5, request_bytes=25, response_bytes=30)
                for _ in range(n)]

    def send(self, events):
        return self.client.post('/agent/v1/ingest',
                                json={'domain_id': self.store.domain_id.hex, 'events': events},
                                headers={'Authorization': 'Bearer ' + self.key})

    def test_first_party_ui_assets_and_strict_csp(self):
        page = self.client.get('/')
        self.assertEqual(page.status_code, 200)
        self.assertIn('Security visibility', page.text)
        self.assertIn('/demo/assets/soc.css', page.text)
        self.assertIn('/demo/assets/soc.js', page.text)
        self.assertNotIn('https://cdn.', page.text)
        self.assertNotIn(self.key, page.text)
        csp = page.headers['content-security-policy']
        self.assertIn("style-src 'self'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("'unsafe-inline'", csp)
        for path, mime in (('/demo/assets/soc.css', 'text/css'),
                           ('/demo/assets/soc.js', 'text/javascript')):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertIn(mime, response.headers['content-type'])
            self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertEqual(self.client.get('/', headers={'Host': 'evil.example'}).status_code, 400)

    def test_dashboard_uses_actual_ingested_events_and_alerts(self):
        events = self.events()
        self.assertEqual(self.send(events).status_code, 200)
        snap = self.store.snapshot()
        self.assertEqual(snap['total_events'], 5)
        self.assertEqual(snap['total_alerts'], 1)
        self.assertEqual(sum(x['count'] for x in snap['overview']['activity']), 5)
        self.assertEqual(snap['overview']['http_status']['4xx'], 5)
        html = self.client.get('/').text
        self.assertIn('Repeated login failures', html)
        self.assertIn('View all alerts', html)
        self.assertIn('Active agent', html)
        self.assertNotIn(self.key, html)
        self.assertNotIn(events[0]['source_ref'], html)
        self.assertEqual(self.client.get('/demo/alerts').status_code, 200)

    def test_key_generation_and_csrf_still_secure(self):
        page = self.client.get('/')
        token = page.cookies['demo_csrf']
        self.assertEqual(self.client.post('/demo/key', data={'_csrf': token},
                         headers={'Origin': 'null'}).status_code, 403)
        issued = self.client.post('/demo/key', data={'_csrf': token},
                                  headers={'Origin': 'http://127.0.0.1:8019'})
        self.assertEqual(issued.status_code, 200)
        self.assertIn('Copy this agent key now', issued.text)
        self.assertIn('csd_', issued.text)
        self.assertNotIn(self.key, issued.text)
        self.assertNotIn('csd_', self.client.get('/').text)

    def test_beta_readiness_is_readonly_blocked_without_secrets(self):
        original = self.store.snapshot()
        result = self.client.get('/demo/readiness')
        self.assertEqual(result.status_code, 200)
        self.assertIn('NO-GO', result.text)
        self.assertIn('12 / 12', result.text)
        self.assertIn('Not evidenced', result.text)
        self.assertIn('Beta readiness', result.text)
        self.assertEqual(original, self.store.snapshot())
        self.assertNotIn(self.key, result.text)
        self.assertNotIn(self.store.domain_id.hex, result.text)

    def test_existing_pages_automatically_use_new_shell(self):
        for path in ('/demo/operations', '/demo/evaluation', '/demo/tuning',
                     '/demo/alerts', '/demo/readiness'):
            page = self.client.get(path)
            self.assertEqual(page.status_code, 200, path)
            self.assertIn('SECURITY OPERATIONS', page.text)
            self.assertIn('skip-link', page.text)
            self.assertNotIn(self.key, page.text)


if __name__ == '__main__':
    unittest.main()
