"""Owner isolation regression against isolated PostgreSQL 17 CI only.

Never connects to Neon: localhost-only guard and dedicated TEST_* variables.
The test controls the backend actor. It does NOT establish resilience to a
stolen runtime PostgreSQL credential, because actor_id is a custom GUC.
"""
from __future__ import annotations

import os
import time
import unittest
import uuid
from urllib.parse import urlsplit

from hosted_api.identity import Identity
from hosted_api.monitoring import MonitoringStore
from hosted_api.postgres import HostedError, HostedStore, identity_id
from scripts.step16_migrate import run as migrate_001
from scripts.step18_migrate import run as migrate_002

ADMIN = os.getenv('CYBERSENTINEL_TEST_PG_ADMIN_DSN', '')
RUNTIME = os.getenv('CYBERSENTINEL_TEST_PG_RUNTIME_DSN', '')


@unittest.skipUnless(ADMIN and RUNTIME, 'Isolated local PostgreSQL 17 CI DSNs required')
class TenantIsolationCI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Explicitly refuse any remote-host TEST DSNs, even if mistakenly exported.
        for dsn in (ADMIN, RUNTIME):
            try:
                parsed = urlsplit(dsn)
            except ValueError as exc:
                raise RuntimeError('Invalid test PostgreSQL DSN') from exc
            if parsed.hostname not in ('127.0.0.1', 'localhost') or parsed.path != '/cybersentinel_stage':
                raise RuntimeError('Tenant integration tests REQUIRE disposable localhost PostgreSQL')
        migrate_001(ADMIN)
        migrate_002(ADMIN)
        cls.domains = HostedStore(RUNTIME)
        cls.monitor = MonitoringStore(RUNTIME)

    def setUp(self):
        nonce = uuid.uuid4().hex
        self.a = Identity('https://issuer.example.org/', 'step36-a-' + nonce)
        self.b = Identity('https://issuer.example.org/', 'step36-b-' + nonce)
        self.domains.ensure_identity(self.a)
        self.domains.ensure_identity(self.b)
        ca = self.domains.create_domain(self.a, 'step36-' + uuid.uuid4().hex + '.org')
        cb = self.domains.create_domain(self.b, 'step36-' + uuid.uuid4().hex + '.org')
        self.a_id, self.b_id = uuid.UUID(ca['id']), uuid.UUID(cb['id'])
        self.domains.verify_domain(self.a, self.a_id, lambda _: [ca['txt_value']])
        self.domains.verify_domain(self.b, self.b_id, lambda _: [cb['txt_value']])

    def test_cross_tenant_ownership_boundaries(self):
        a_key = self.monitor.issue_key(self.a, self.a_id, 'owner-a')
        self.assertEqual(len(self.monitor.list_keys(self.a, self.a_id)), 1)
        with self.assertRaises(HostedError):
            self.monitor.list_keys(self.b, self.a_id)
        with self.assertRaises(HostedError):
            self.monitor.recent(self.b, self.a_id)
        with self.assertRaises(HostedError):
            self.monitor.list_alerts(self.b, self.a_id)
        with self.assertRaises(HostedError):
            self.monitor.issue_key(self.b, self.a_id, 'attempt')
        events = [dict(event_id=uuid.uuid4().hex, occurred_at=int(time.time()),
                       source_ref='a' * 32, method='POST', path_group='login',
                       status_code=401, duration_ms=1.0, request_bytes=0,
                       response_bytes=0) for _ in range(5)]
        result = self.monitor.ingest(a_key['agent_key'], self.a_id, events)
        self.assertEqual(result['accepted'], 5)
        self.assertEqual(self.monitor.list_alerts(self.a, self.a_id)['total_alerts'], 1)
        self.assertEqual(self.monitor.list_alerts(self.b, self.b_id)['total_alerts'], 0)
        with self.assertRaises(HostedError):
            self.monitor.ingest(a_key['agent_key'], self.b_id, events)
        alert = uuid.UUID(self.monitor.list_alerts(self.a, self.a_id)['alerts'][0]['id'])
        with self.assertRaises(HostedError):
            self.monitor.acknowledge(self.b, self.b_id, alert)
        with self.assertRaises(HostedError):
            self.monitor.revoke_key(self.b, self.b_id, uuid.UUID(a_key['id']))

    def test_scoped_runtime_queries_and_actor_reset(self):
        self.monitor.issue_key(self.a, self.a_id, 'key-a')
        self.monitor.issue_key(self.b, self.b_id, 'key-b')
        with self.monitor._connect() as db:
            self.monitor._set_actor(db, identity_id(self.a))
            keys_a = db.execute('SELECT count(*) AS n FROM cs.agent_keys').fetchone()['n']
            self.assertEqual(keys_a, 1)
            self.monitor._set_actor(db, identity_id(self.b))
            self.assertEqual(db.execute('SELECT count(*) AS n FROM cs.agent_keys').fetchone()['n'], 1)
        # A new unscoped connection sees no rows; the transaction-local actor did not leak.
        with self.monitor._connect() as db:
            for table in ('identities', 'domains', 'agent_keys', 'telemetry_events', 'detection_alerts'):
                self.assertEqual(db.execute('SELECT count(*) AS n FROM cs.' + table).fetchone()['n'], 0)


if __name__ == '__main__':
    unittest.main()
