"""Full CI-only role-bound canary, rotation and session revocation drills.

Guards forbid remote Neon/staging. All rows and tenant identities are synthetic.
"""
from __future__ import annotations

import os
import unittest
import uuid

from scripts.step39_actor_boundary import disposable_test_dsn
from scripts.step47_schema_rehearsal import DisposableSchemaRehearsal
from scripts.step49_credential_broker import DisposableCredentialBroker
from scripts.step51_application_canary import IsolatedApplicationCanary

ADMIN = os.getenv('CYBERSENTINEL_TEST_PG_ADMIN_DSN', '')
ENABLED = (os.getenv('GITHUB_ACTIONS') == 'true'
           and os.getenv('CYBERSENTINEL_ISOLATED_PG_CI') == '1'
           and ADMIN.startswith('postgresql://postgres:ci-ephemeral-admin@127.0.0.1:5432/')
           and disposable_test_dsn(ADMIN))


class FixtureVerifier:
    """Only used to exercise broker behavior with synthetic CI identities."""

    def verify(self, bearer):
        from hosted_api.identity import Identity
        if bearer == 'ci-a':
            return Identity('https://ci.example.invalid/', 'tenant-a')
        if bearer == 'ci-b':
            return Identity('https://ci.example.invalid/', 'tenant-b')
        raise PermissionError('Invalid synthetic token')


@unittest.skipUnless(ENABLED, 'Only isolated PostgreSQL 17 GitHub CI')
class TenantBrokerCanaryPostgres(unittest.TestCase):
    def setUp(self):
        self.scenario = DisposableSchemaRehearsal(ADMIN)
        try:
            self.scenario.prepare()
            self.scenario.install_additive_policies()
            self.scenario.seed_synthetic()
            self.broker = DisposableCredentialBroker(
                self.scenario, FixtureVerifier(), (
                    ('https://ci.example.invalid/', 'tenant-a', self.scenario.roles[0]),
                    ('https://ci.example.invalid/', 'tenant-b', self.scenario.roles[1]),
                ))
            self.canary = IsolatedApplicationCanary(self.broker)
        except Exception:
            self.scenario.close()
            raise

    def tearDown(self):
        self.scenario.close()

    def test_canary_reads_and_updates_only_own_tenant(self):
        a = self.canary.overview('ci-a')
        b = self.canary.overview('ci-b')
        for overview in (a, b):
            self.assertEqual(len(overview['domains']), 1)
            self.assertEqual(len(overview['alerts']), 1)
            self.assertEqual(overview['events'], 1)
            self.assertEqual(overview['agent_keys'], 1)
            self.assertEqual(overview['identities'], 1)
        self.assertNotEqual(a['domains'][0]['id'], b['domains'][0]['id'])
        a_alert = uuid.UUID(a['alerts'][0]['id'])
        b_alert = uuid.UUID(b['alerts'][0]['id'])
        self.assertFalse(self.canary.acknowledge('ci-a', b_alert))
        self.assertTrue(self.canary.acknowledge('ci-a', a_alert))
        self.assertEqual(self.canary.overview('ci-a')['alerts'][0]['status'], 'acknowledged')
        self.assertEqual(self.canary.overview('ci-b')['alerts'][0]['status'], 'open')
        with self.assertRaises(PermissionError):
            self.canary.overview('arbitrary-user')

    def test_rotation_invalidates_old_password_but_not_existing_session(self):
        import psycopg
        from psycopg.conninfo import make_conninfo
        old = make_conninfo(self.scenario.admin_dsn, dbname=self.scenario.name,
                            user=self.scenario.roles[0], password=self.scenario.passwords[0])
        with self.broker.session('ci-a') as already_authenticated:
            self.broker._ci_operator_rotate(0)
            # Important limitation: rotation is NOT existing-session revocation.
            self.assertEqual(already_authenticated.execute('SELECT session_user').fetchone()[0],
                             self.scenario.roles[0])
        with self.assertRaises(psycopg.OperationalError):
            psycopg.connect(old, connect_timeout=4)
        self.assertEqual(self.canary.overview('ci-a')['events'], 1)
        self.assertEqual(self.canary.overview('ci-b')['events'], 1)

    def test_disable_terminates_old_sessions_and_preserves_other_tenant(self):
        import psycopg
        with self.broker.session('ci-a') as old_a:
            with self.broker.session('ci-b') as live_b:
                terminated = self.broker._ci_operator_disable_and_terminate(0)
                self.assertGreaterEqual(terminated, 1)
                with self.assertRaises(psycopg.Error):
                    old_a.execute('SELECT 1')
                self.assertEqual(live_b.execute('SELECT session_user').fetchone()[0],
                                 self.scenario.roles[1])
        with self.assertRaises(PermissionError):
            with self.broker.session('ci-a'):
                self.fail('Disabled session unexpectedly succeeded')
        self.assertEqual(self.canary.overview('ci-b')['events'], 1)

    def test_role_scope_ignores_guc_spoof_and_rejects_cross_tenant_write(self):
        import psycopg
        with self.broker.session('ci-a') as db:
            db.execute('SELECT set_config(%s, %s, false)',
                       ('cs.actor_id', str(self.scenario.owners[1])))
            self.assertEqual(db.execute('SELECT count(*) FROM cs.domains').fetchone()[0], 1)
            with self.assertRaises(psycopg.Error):
                db.execute('UPDATE cs.domains SET owner_id = %s WHERE id = %s',
                           (self.scenario.owners[1], self.scenario.synthetic_domain_ids[0]))
        with self.assertRaises(PermissionError):
            self.broker._resolve('ci-not-registered')


if __name__ == '__main__':
    unittest.main()
