"""Full five-table additive RLS and rollback rehearsal in disposable PG 17."""
from __future__ import annotations

import os
import unittest

from scripts.step39_actor_boundary import disposable_test_dsn
from scripts.step47_schema_rehearsal import DisposableSchemaRehearsal, TABLES

ADMIN = os.getenv('CYBERSENTINEL_TEST_PG_ADMIN_DSN', '')
ENABLED = (os.getenv('GITHUB_ACTIONS') == 'true'
           and os.getenv('CYBERSENTINEL_ISOLATED_PG_CI') == '1'
           and ADMIN.startswith('postgresql://postgres:ci-ephemeral-admin@127.0.0.1:5432/')
           and disposable_test_dsn(ADMIN))


@unittest.skipUnless(ENABLED, 'Only isolated PostgreSQL 17 GitHub CI')
class FiveTableRLSRehearsal(unittest.TestCase):
    def test_additive_policies_cross_tenant_and_rollback(self):
        import psycopg
        from psycopg import sql
        scenario = DisposableSchemaRehearsal(ADMIN)
        try:
            scenario.prepare()
            scenario.install_additive_policies()
            scenario.seed_synthetic()
            scenario.assert_tenant_scope()
            with scenario._admin() as db:
                flags = db.execute('''SELECT rolsuper, rolbypassrls, rolcreaterole,
                    rolcreatedb, rolinherit FROM pg_roles WHERE rolname = ANY(%s)''',
                    (list(scenario.roles),)).fetchall()
                self.assertEqual(len(flags), 2)
                self.assertTrue(all(not any(row) for row in flags))
            with scenario.tenant(0) as db:
                # The tenant can perform an authorized update to its own row.
                new_domain = 'changed-' + scenario.name + '.example.org'
                changed = db.execute('UPDATE cs.domains SET domain=%s WHERE id=%s',
                                     (new_domain, scenario.synthetic_domain_ids[0]))
                self.assertEqual(changed.rowcount, 1)
                self.assertEqual(db.execute('SELECT domain FROM cs.domains').fetchone()[0], new_domain)
                # The login cannot modify immutable tenant mappings.
                with self.assertRaises(psycopg.Error):
                    db.execute('UPDATE cs.tenant_login_map SET owner_id=%s',
                               (scenario.owners[1],))
                db.rollback()
                # The login cannot impersonate another tenant's DB role.
                with self.assertRaises(psycopg.Error):
                    db.execute(sql.SQL('SET ROLE {}').format(sql.Identifier(scenario.roles[1])))
                db.rollback()
                # A writable tenant table must not permit changing row ownership.
                with self.assertRaises(psycopg.Error):
                    db.execute('UPDATE cs.domains SET owner_id=%s WHERE id=%s',
                               (scenario.owners[1], scenario.synthetic_domain_ids[0]))
                db.rollback()
                # SELECT policy must remain scoped after failed writes.
                self.assertEqual(db.execute('SELECT count(*) FROM cs.domains').fetchone()[0], 1)
            scenario.rollback()
            self.assertTrue(scenario.reverted)
            with scenario._admin() as db:
                remaining = db.execute('SELECT count(*) FROM pg_roles WHERE rolname = ANY(%s)',
                                       (list(scenario.roles),)).fetchone()[0]
                self.assertEqual(remaining, 0)
                for table in TABLES:
                    self.assertIn((table, next(n for t, n in scenario.baseline_policies if t == table)),
                                  scenario._policies())
        finally:
            scenario.close()


if __name__ == '__main__':
    unittest.main()
