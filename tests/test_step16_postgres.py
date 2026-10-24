"""Actual PostgreSQL RLS integration; CI provides dedicated role + database."""
from __future__ import annotations

import os
import unittest
import uuid

from hosted_api.identity import Identity
from hosted_api.postgres import HostedError, HostedStore, identity_id
from scripts.step16_migrate import run


@unittest.skipUnless(os.environ.get('CYBERSENTINEL_TEST_PG_ADMIN_DSN') and
                     os.environ.get('CYBERSENTINEL_TEST_PG_RUNTIME_DSN'),
                     'PostgreSQL integration requires dedicated CI test DSNs')
class PostgresRLSIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin = os.environ['CYBERSENTINEL_TEST_PG_ADMIN_DSN']
        cls.runtime = os.environ['CYBERSENTINEL_TEST_PG_RUNTIME_DSN']
        cls.initial = run(cls.admin)
        cls.store = HostedStore(cls.runtime)

    def setUp(self):
        nonce = uuid.uuid4().hex
        self.a = Identity('https://issuer.example.org/', 'a-' + nonce)
        self.b = Identity('https://issuer.example.org/', 'b-' + nonce)
        self.store.ensure_identity(self.a)
        self.store.ensure_identity(self.b)

    def test_migration_checksum_and_rls_enabled(self):
        self.assertIn(run(self.admin)['status'], ('already-applied',))
        import psycopg
        with psycopg.connect(self.admin) as db:
            rows = db.execute("""SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class
                WHERE oid IN ('cs.identities'::regclass,'cs.domains'::regclass)""").fetchall()
        self.assertEqual(len(rows),2)
        self.assertTrue(all(r[1] and r[2] for r in rows))

    def test_runtime_role_cannot_bypass_rls(self):
        with self.store._connect() as db:
            self.store._set_actor(db,identity_id(self.a))
            who=db.execute('SELECT current_user').fetchone()['current_user']
            self.assertEqual(who,'cybersentinel_runtime')
            self.assertEqual(db.execute('SELECT count(*) AS n FROM cs.identities').fetchone()['n'],1)

    def test_identity_and_domain_hidden_from_other_owner(self):
        claim = self.store.create_domain(self.a, 'a-' + uuid.uuid4().hex + '.org')
        self.assertEqual(len(self.store.list_domains(self.a)),1)
        self.assertEqual(self.store.list_domains(self.b),[])
        with self.assertRaises(HostedError) as ctx:
            self.store.pending_proof(self.b,uuid.UUID(claim['id']))
        self.assertEqual(ctx.exception.code,404)
        with self.store._connect() as db:
            # No request actor context; policy must be default-deny.
            rows = db.execute('SELECT id FROM cs.identities').fetchall()
            self.assertEqual(rows,[])

    def test_dns_proof_is_owner_scoped_and_single_owner(self):
        site = 'cs-' + uuid.uuid4().hex + '.org'
        a = self.store.create_domain(self.a,site)
        b = self.store.create_domain(self.b,site)
        rec = {a['txt_name']: [a['txt_value']]}
        verified = self.store.verify_domain(self.a,uuid.UUID(a['id']),lambda name: rec.get(name, []))
        self.assertTrue(verified['verified'])
        rec[b['txt_name']] = [b['txt_value']]
        with self.assertRaises(HostedError) as ctx:
            self.store.verify_domain(self.b,uuid.UUID(b['id']),lambda name: rec.get(name, []))
        self.assertEqual(ctx.exception.code,409)

    def test_invalid_dns_record_not_verified(self):
        claim=self.store.create_domain(self.a,'z-' + uuid.uuid4().hex + '.org')
        with self.assertRaises(HostedError) as ctx:
            self.store.verify_domain(self.a,uuid.UUID(claim['id']),lambda _: ['forged'])
        self.assertEqual(ctx.exception.code,422)


if __name__ == '__main__':
    unittest.main()
