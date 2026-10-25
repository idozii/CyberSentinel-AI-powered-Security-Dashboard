"""Step 55-57 security boundary tests: only on GitHub disposable PostgreSQL 17."""
from __future__ import annotations

import os
import unittest

from scripts.step39_actor_boundary import disposable_test_dsn
from scripts.step47_schema_rehearsal import DisposableSchemaRehearsal, TABLES
from scripts.step49_credential_broker import DisposableCredentialBroker
from scripts.step52_credential_custody import DisposableCredentialCustody
from hosted_api.tenant_session_boundary import TenantSessionBoundary
from scripts.step56_boundary_canary import IsolatedTenantBoundaryCanary

ADMIN = os.getenv('CYBERSENTINEL_TEST_PG_ADMIN_DSN','')
ENABLED = (os.getenv('GITHUB_ACTIONS') == 'true'
           and os.getenv('CYBERSENTINEL_ISOLATED_PG_CI') == '1'
           and ADMIN.startswith('postgresql://postgres:ci-ephemeral-admin@127.0.0.1:5432/')
           and disposable_test_dsn(ADMIN))


class SyntheticVerifier:
    def verify(self, bearer):
        from hosted_api.identity import Identity
        if bearer == 'ci-tenant-a':
            return Identity('https://ci.example.invalid/','tenant-a')
        if bearer == 'ci-tenant-b':
            return Identity('https://ci.example.invalid/','tenant-b')
        raise PermissionError('Rejected fixture token')


@unittest.skipUnless(ENABLED,'Requires GitHub Actions disposable PostgreSQL 17')
class BoundaryPostgresProof(unittest.TestCase):
    def setUp(self):
        self.scenario=DisposableSchemaRehearsal(ADMIN)
        try:
            self.scenario.prepare()
            self.scenario.install_additive_policies()
            self.scenario.seed_synthetic()
            broker=DisposableCredentialBroker(self.scenario,SyntheticVerifier(),(
                ('https://ci.example.invalid/','tenant-a',self.scenario.roles[0]),
                ('https://ci.example.invalid/','tenant-b',self.scenario.roles[1]),
            ))
            self.custody=DisposableCredentialCustody(broker)
            self.boundary=TenantSessionBoundary(self.custody,max_per_tenant=1)
            self.canary=IsolatedTenantBoundaryCanary(self.boundary)
        except Exception:
            self.scenario.close()
            raise

    def tearDown(self):
        self.scenario.close()

    def test_five_tables_separated_and_auth_denied(self):
        self.assertEqual(self.canary.overview('ci-tenant-a'),{t:1 for t in TABLES})
        self.assertEqual(self.canary.overview('ci-tenant-b'),{t:1 for t in TABLES})
        with self.assertRaises(PermissionError):
            self.canary.overview('not-provisioned')
        with self.boundary.borrow('ci-tenant-a') as a:
            who=a.execute('SELECT session_user,current_user').fetchone()
            self.assertEqual(who,(self.scenario.roles[0],)*2)
            a.execute('BEGIN')
            try:
                a.execute('SELECT set_config(%s,%s,true)',
                          ('cs.actor_id',str(self.scenario.owners[1])))
                self.assertEqual(a.execute('SELECT count(*) FROM cs.domains').fetchone()[0],1)
            finally:
                a.execute('ROLLBACK')
        self.assertEqual(self.boundary.report()['active_fixture_sessions'],0)

    def test_capacity_denial_is_tenant_specific(self):
        with self.boundary.borrow('ci-tenant-a'):
            with self.assertRaises(PermissionError):
                with self.boundary.borrow('ci-tenant-a'):
                    self.fail('Concurrent session cap bypassed')
            with self.boundary.borrow('ci-tenant-b') as other:
                self.assertEqual(other.execute('SELECT count(*) FROM cs.agent_keys').fetchone()[0],1)
        self.assertGreaterEqual(self.boundary.report()['denied_requests'],1)

    def test_disable_terminates_old_role_but_preserves_other(self):
        import psycopg
        with self.boundary.borrow('ci-tenant-a') as old_a:
            with self.boundary.borrow('ci-tenant-b') as b:
                terminated=self.boundary._ci_operator_disable(0)
                self.assertGreaterEqual(terminated,1)
                with self.assertRaises(PermissionError):
                    with self.boundary.borrow('ci-tenant-a'):
                        self.fail('Disabled tenant authenticated')
                with self.assertRaises(psycopg.Error):
                    old_a.execute('SELECT 1')
                self.assertEqual(b.execute('SELECT current_user').fetchone()[0],self.scenario.roles[1])
        self.assertEqual(self.canary.overview('ci-tenant-b')['telemetry_events'],1)
        self.assertEqual(self.boundary.report()['blocked_fixture_logins'],1)
        self.boundary.seal()
        with self.assertRaises(RuntimeError):
            self.canary.overview('ci-tenant-b')


if __name__=='__main__':
    unittest.main()
