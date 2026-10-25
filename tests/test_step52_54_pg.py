"""Step 52-54 real PostgreSQL 17 CI-only cutover and custody drills.

Never execute against Neon, real users, or a non-disposable database.
"""
from __future__ import annotations

import os
import unittest
import uuid

from scripts.step39_actor_boundary import disposable_test_dsn
from scripts.step47_schema_rehearsal import DisposableSchemaRehearsal, TABLES
from scripts.step49_credential_broker import DisposableCredentialBroker
from scripts.step52_credential_custody import DisposableCredentialCustody
from scripts.step53_cutover_drill import DisposableCutoverDrill

ADMIN = os.environ.get('CYBERSENTINEL_TEST_PG_ADMIN_DSN', '')
ENABLED = (os.environ.get('GITHUB_ACTIONS') == 'true'
           and os.environ.get('CYBERSENTINEL_ISOLATED_PG_CI') == '1'
           and ADMIN.startswith('postgresql://postgres:ci-ephemeral-admin@127.0.0.1:5432/')
           and disposable_test_dsn(ADMIN))


class SyntheticVerifier:
    def verify(self, bearer):
        from hosted_api.identity import Identity
        if bearer == 'ci-a':
            return Identity('https://ci.example.invalid/', 'tenant-a')
        if bearer == 'ci-b':
            return Identity('https://ci.example.invalid/', 'tenant-b')
        raise PermissionError('Invalid fixture token')


@unittest.skipUnless(ENABLED, 'Only GitHub Actions disposable PostgreSQL 17')
class CustodyCutoverPg(unittest.TestCase):
    def setUp(self):
        self.scenario = DisposableSchemaRehearsal(ADMIN)
        try:
            self.scenario.prepare()
            self.scenario.install_additive_policies()
            self.scenario.seed_synthetic()
            self.broker = DisposableCredentialBroker(self.scenario, SyntheticVerifier(), (
                ('https://ci.example.invalid/', 'tenant-a', self.scenario.roles[0]),
                ('https://ci.example.invalid/', 'tenant-b', self.scenario.roles[1])))
            self.custody = DisposableCredentialCustody(self.broker)
            self.drill = DisposableCutoverDrill(self.scenario, self.custody)
        except Exception:
            self.scenario.close()
            raise

    def tearDown(self):
        self.scenario.close()

    def _canary(self):
        self.drill.begin_shadow()
        for idx, bearer in enumerate(('ci-a','ci-b')):
            counts = self.drill.shadow_probe(bearer,idx)
            self.assertEqual(counts,{table:1 for table in TABLES})
        self.drill.activate_canary()

    def test_identity_shadow_cutover_and_fail_closed_dependency_rollback(self):
        self._canary()
        self.assertEqual(self.drill.canary_overview('ci-a'),{t:1 for t in TABLES})
        with self.assertRaises(PermissionError):
            self.drill.canary_overview('invalid-token')
        with self.scenario._admin() as db:
            alert_b = db.execute('SELECT id FROM cs.detection_alerts WHERE owner_id=%s',
                                 (self.scenario.owners[1],)).fetchone()[0]
            alert_a = db.execute('SELECT id FROM cs.detection_alerts WHERE owner_id=%s',
                                 (self.scenario.owners[0],)).fetchone()[0]
        self.assertFalse(self.drill.canary_acknowledge('ci-a',alert_b))
        self.assertTrue(self.drill.canary_acknowledge('ci-a',alert_a))
        self.drill.rollback('dependency_outage')
        with self.assertRaises(RuntimeError):
            self.drill.canary_overview('ci-b')
        with self.assertRaises(RuntimeError):
            with self.custody.session('ci-a'):
                self.fail('Unexpected session after seal')
        with self.scenario._admin() as db:
            for table in TABLES:
                from psycopg import sql
                n = db.execute(sql.SQL('SELECT count(*) FROM cs.{}').format(
                    sql.Identifier(table))).fetchone()[0]
                self.assertEqual(n,2)
        self.assertFalse(self.drill.report()['staging_cutover_performed'])

    def test_wrong_fixture_identity_for_shadow_rolls_back(self):
        self.drill.begin_shadow()
        with self.assertRaises(AssertionError):
            self.drill.shadow_probe('ci-b', 0)
        self.assertEqual(self.drill.phase, 'rolled_back')
        with self.assertRaises(RuntimeError):
            self.drill.activate_canary()

    def test_redacted_custody_rotation_and_disable_isolated_tenant(self):
        import psycopg
        self._canary()
        with self.custody.session('ci-a') as old_a:
            with self.custody.session('ci-b') as untouched_b:
                self.custody._ci_operator_rotate(0)
                self.assertEqual(old_a.execute('SELECT session_user').fetchone()[0],
                                 self.scenario.roles[0])
                n = self.custody._ci_operator_disable(0)
                self.assertGreaterEqual(n, 1)
                with self.assertRaises(psycopg.Error):
                    old_a.execute('SELECT 1')
                self.assertEqual(untouched_b.execute('SELECT session_user').fetchone()[0],
                                 self.scenario.roles[1])
        with self.assertRaises(PermissionError):
            with self.custody.session('ci-a'):
                self.fail('Disabled tenant was reauthenticated')
        self.assertEqual(self.drill.canary_overview('ci-b')['telemetry_events'], 1)
        audit=self.custody.report()
        self.assertEqual((audit['rotations'],audit['disabled_fixture_logins']),(1,1))
        rendered=str(audit)
        for secret in self.scenario.passwords:
            self.assertNotIn(secret,rendered)
        self.drill.rollback('security_regression')
        self.assertFalse(self.drill.report()['fallback_to_shared_runtime'])


if __name__ == '__main__':
    unittest.main()
