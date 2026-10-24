"""Offline regression for Steps 26-30, strictly no real tenant credentials."""
from __future__ import annotations

import json
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from hosted_api.local_demo import DemoStore, create_demo_app
from scripts.step26_30_preflight import check as preflight
from scripts.step27_tenant_audit import offline_audit
from scripts.step29_reliability_drill import reliability_drill
from scripts.step30_beta_gate import DEFAULT, KEYS, assess
from scripts.step26_30_release import rehearse


class Steps2630Test(unittest.TestCase):
    def setUp(self):
        self.store = DemoStore()
        self.client = TestClient(create_demo_app(self.store, enabled=True), follow_redirects=False)
        self.key = self.store.issue_key()

    def tearDown(self):
        self.client.close()

    def _event(self, uid=None):
        return dict(event_id=uid or uuid.uuid4().hex, occurred_at=int(time.time()),
                    source_ref='a' * 32, method='GET', path_group='login',
                    status_code=401, duration_ms=1.0, request_bytes=14, response_bytes=5)

    def _send(self, items, token=None):
        return self.client.post('/agent/v1/ingest', json={
            'domain_id': self.store.domain_id.hex, 'events': items},
            headers={'Authorization': 'Bearer ' + (self.key if token is None else token)})

    def test_operations_are_aggregate_and_secret_free(self):
        resp = self.client.get('/demo/operations.json')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['counts']['keys_issued'], 1)
        self.assertEqual(resp.json()['events_in_memory'], 0)
        self.assertNotIn(self.key, resp.text)
        self.assertNotIn(self.store.domain_id.hex, resp.text)
        self.assertNotIn('token_hash', resp.text)
        self.assertEqual(resp.headers['cache-control'], 'no-store')
        self.assertEqual(resp.json()['persistent'], False)

    def test_operations_counters_replay_and_auth_denied(self):
        events = [self._event() for _ in range(5)]
        self.assertEqual(self._send(events).status_code, 200)
        self.assertEqual(self._send(events).status_code, 200)
        self.assertEqual(self._send(events, token='csd_wrong').status_code, 401)
        counts = self.client.get('/demo/operations.json').json()['counts']
        self.assertEqual(counts['batches_received'], 3)
        self.assertEqual(counts['events_accepted'], 5)
        self.assertEqual(counts['duplicates_ignored'], 5)
        self.assertEqual(counts['alerts_updated'], 1)
        self.assertEqual(counts['invalid_credentials'], 1)

    def test_html_operations_and_no_metrics_in_public(self):
        self.assertEqual(self.client.get('/demo/operations').status_code, 200)
        page = self.client.get('/demo/operations').text
        self.assertIn('Local operations - Step 28', page)
        self.assertNotIn(self.key, page)
        self.assertIn('local operational counters', self.client.get('/').text)
        self.assertEqual(self.client.get('/metrics').status_code, 404)

    def test_invalid_batch_does_not_count_accepted(self):
        expired = self._event()
        expired['occurred_at'] -= 900
        self.assertEqual(self._send([expired]).status_code, 422)
        r = self.client.get('/demo/operations.json').json()['counts']
        self.assertEqual(r['events_accepted'], 0)
        self.assertEqual(r['invalid_events'], 1)

    def test_deployment_preflight_and_local_sandbox(self):
        self.assertEqual(offline_audit()['status'], 'pass')
        self.assertEqual(preflight()['status'], 'pass')

    def test_beta_checklist_fails_closed(self):
        evidence = json.loads(DEFAULT.read_text())
        result = assess(evidence)
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(len(result['missing_conditions']), len(KEYS))
        self.assertFalse(result['authorization_to_deploy_publicly'])
        with self.assertRaises(ValueError):
            assess({**evidence, 'secrets': 'should_not_be_logged'})
        with self.assertRaises(ValueError):
            assess({**evidence, 'privacy_legal_approval': 1})

    def test_even_self_attested_all_true_is_not_public_approval(self):
        r = assess({key: True for key in KEYS})
        self.assertEqual(r['status'], 'manual_independent_review_required')
        self.assertFalse(r['authorization_to_deploy_publicly'])

    def test_focused_reliability_drill(self):
        report = reliability_drill()
        self.assertEqual(report['status'], 'pass')
        self.assertTrue(all(report['checks'].values()))

    def test_combined_release_reports_blocked_beta(self):
        report = rehearse()
        self.assertEqual(report['status'], 'pass')
        self.assertEqual(report['beta_gate'], 'blocked')
        self.assertGreater(report['beta_conditions_outstanding'], 0)
        self.assertTrue(all(report['checks'].values()))


if __name__ == '__main__':
    unittest.main()
