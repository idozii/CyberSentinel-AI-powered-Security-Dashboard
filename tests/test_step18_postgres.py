"""Real PostgreSQL 17 tests run by the dedicated CI service, never live Neon."""
from __future__ import annotations

import os
import time
import unittest
import uuid

from hosted_api.identity import Identity
from hosted_api.monitoring import MonitoringStore
from hosted_api.postgres import HostedError, HostedStore, identity_id
from scripts.step16_migrate import run as migrate_001
from scripts.step18_migrate import run as migrate_002


@unittest.skipUnless(os.getenv('CYBERSENTINEL_TEST_PG_ADMIN_DSN') and
                     os.getenv('CYBERSENTINEL_TEST_PG_RUNTIME_DSN'),
                     'Real PostgreSQL 17 integration requires isolated CI DSNs')
class MonitoringPostgresIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin = os.environ['CYBERSENTINEL_TEST_PG_ADMIN_DSN']
        cls.runtime = os.environ['CYBERSENTINEL_TEST_PG_RUNTIME_DSN']
        migrate_001(cls.admin)
        migrate_002(cls.admin)
        cls.ops = MonitoringStore(cls.runtime)
        cls.domains = HostedStore(cls.runtime)

    def setUp(self):
        nonce = uuid.uuid4().hex
        self.a = Identity('https://issuer.example.org/', 'step18-a-'+nonce)
        self.b = Identity('https://issuer.example.org/', 'step18-b-'+nonce)
        self.domains.ensure_identity(self.a)
        self.domains.ensure_identity(self.b)
        self.a_claim = self.domains.create_domain(self.a, 'step18-'+uuid.uuid4().hex+'.org')
        self.b_claim = self.domains.create_domain(self.b, 'step18-'+uuid.uuid4().hex+'.org')
        self.a_id = uuid.UUID(self.a_claim['id'])
        self.b_id = uuid.UUID(self.b_claim['id'])
        self.domains.verify_domain(self.a, self.a_id, lambda _:[self.a_claim['txt_value']])
        self.domains.verify_domain(self.b, self.b_id, lambda _:[self.b_claim['txt_value']])

    @staticmethod
    def events(count=5, *, status=401):
        t = int(time.time())
        src = uuid.uuid4().hex
        return [dict(event_id=uuid.uuid4().hex, occurred_at=t, source_ref=src,
                     method='GET', path_group='login', status_code=status,
                     duration_ms=1.4, request_bytes=24, response_bytes=10)
                for _ in range(count)]

    def test_migration_checksum_and_rls_policy(self):
        self.assertEqual(migrate_002(self.admin)['status'], 'already-applied')
        import psycopg
        with psycopg.connect(self.admin) as db:
            rows = db.execute('''SELECT relname,relrowsecurity,relforcerowsecurity
                 FROM pg_class WHERE oid IN ('cs.agent_keys'::regclass,
                 'cs.telemetry_events'::regclass,'cs.detection_alerts'::regclass)''').fetchall()
        self.assertEqual(len(rows),3)
        self.assertTrue(all(r[1] and r[2] for r in rows))

    def test_tokens_stored_only_as_hash_and_no_cross_tenant_access(self):
        key = self.ops.issue_key(self.a, self.a_id,'nginx-agent')
        self.assertTrue(key['agent_key'].startswith('csp_'))
        self.assertEqual(len(self.ops.list_keys(self.a,self.a_id)),1)
        with self.ops._connect() as db:
            self.ops._set_actor(db,identity_id(self.a))
            row = db.execute('SELECT token_hash FROM cs.agent_keys WHERE id=%s',
                             (uuid.UUID(key['id']),)).fetchone()
            self.assertEqual(len(row['token_hash']),64)
            self.assertNotEqual(row['token_hash'],key['agent_key'])
        self.assertEqual(self.ops.list_keys(self.b,self.b_id),[])
        with self.assertRaises(HostedError) as failure:
            self.ops.list_keys(self.b,self.a_id)
        self.assertEqual(failure.exception.code,404)
        with self.ops._connect() as db:
            self.assertEqual(db.execute('SELECT count(*) AS n FROM cs.agent_keys').fetchone()['n'],0)

    def test_verified_domain_required_and_key_limit(self):
        unverified = self.domains.create_domain(self.a,'step18-'+uuid.uuid4().hex+'.net')
        with self.assertRaises(HostedError):
            self.ops.issue_key(self.a, uuid.UUID(unverified['id']),'no-verification')
        for i in range(3):
            self.ops.issue_key(self.a,self.a_id,f'agent-{i}')
        with self.assertRaises(HostedError) as failure:
            self.ops.issue_key(self.a,self.a_id,'fourth')
        self.assertEqual(failure.exception.code,429)

    def test_ingest_idempotency_alerts_ack_and_revoke(self):
        key = self.ops.issue_key(self.a,self.a_id,'production-like-test')
        token = key['agent_key']
        events = self.events()
        first = self.ops.ingest(token,self.a_id,events)
        self.assertEqual((first['accepted'],first['duplicates'],first['alerts_updated']), (5,0,1))
        second = self.ops.ingest(token,self.a_id,events)
        self.assertEqual((second['accepted'],second['duplicates'],second['alerts_updated']), (0,5,0))
        self.assertEqual(self.ops.recent(self.a,self.a_id)['total_events'],5)
        alerts = self.ops.list_alerts(self.a,self.a_id)
        self.assertEqual(alerts['total_alerts'],1)
        self.assertEqual(alerts['alerts'][0]['rule_id'],'repeated_login_failures')
        ack = self.ops.acknowledge(self.a,self.a_id,uuid.UUID(alerts['alerts'][0]['id']))
        self.assertEqual(ack['status'],'acknowledged')
        self.assertEqual(self.ops.list_alerts(self.a,self.a_id,status='open')['total_alerts'],0)
        self.assertEqual(self.ops.list_alerts(self.a,self.a_id,status='acknowledged')['total_alerts'],1)
        self.assertEqual(self.ops.list_alerts(self.b,self.b_id)['total_alerts'],0)
        with self.ops._connect() as db:
            self.assertEqual(db.execute('SELECT count(*) AS n FROM cs.telemetry_events').fetchone()['n'],0)
            self.assertEqual(db.execute('SELECT count(*) AS n FROM cs.detection_alerts').fetchone()['n'],0)
        with self.assertRaises(HostedError):
            self.ops.acknowledge(self.b,self.b_id,uuid.UUID(alerts['alerts'][0]['id']))
        with self.assertRaises(HostedError):
            self.ops.ingest(token,self.b_id,events)
        with self.assertRaises(HostedError):
            self.ops.revoke_key(self.b,self.b_id,uuid.UUID(key['id']))
        self.ops.revoke_key(self.a,self.a_id,uuid.UUID(key['id']))
        with self.assertRaises(HostedError) as failure:
            self.ops.ingest(token,self.a_id,events)
        self.assertEqual(failure.exception.code,401)


if __name__ == '__main__':
    unittest.main()
