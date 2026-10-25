"""Only GitHub Actions disposable PostgreSQL 17 may run these fixture tests."""
from __future__ import annotations

import os
import unittest
import uuid

from scripts.step39_actor_boundary import disposable_test_dsn
from scripts.step41_role_boundary import (delete_disposable, install_disposable,
                                         make_fixture, tenant_dsn, protected_ci)

ADMIN = os.environ.get('CYBERSENTINEL_TEST_PG_ADMIN_DSN', '')
ENABLED = (os.environ.get('GITHUB_ACTIONS') == 'true'
           and os.environ.get('CYBERSENTINEL_ISOLATED_PG_CI') == '1'
           and bool(ADMIN) and disposable_test_dsn(ADMIN)
           and ADMIN.startswith('postgresql://postgres:ci-ephemeral-admin@127.0.0.1:5432/'))


@unittest.skipUnless(ENABLED, 'Step 41 runs only on ephemeral PostgreSQL GitHub Actions')
class TenantRoleIsolationPg(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        cls.pg = psycopg
        cls.fixture = make_fixture()
        install_disposable(ADMIN, cls.fixture)

    @classmethod
    def tearDownClass(cls):
        delete_disposable(ADMIN, cls.fixture)

    def test_login_role_ignores_spoofed_actor_and_cannot_cross_tenant(self):
        from psycopg import sql
        f = self.fixture
        for i in (0, 1):
            other = 1 - i
            with self.pg.connect(tenant_dsn(ADMIN, f, i)) as db:
                table = sql.SQL('{}.tenant_events').format(sql.Identifier(f.schema))
                own = db.execute(sql.SQL('SELECT owner_id FROM {}').format(table)).fetchall()
                self.assertEqual([r[0] for r in own], [f.owners[i]])
                # Mutable GUC from old design is ignored by the new role-bound policy.
                db.execute('SELECT set_config(%s,%s,true)', ('cs.actor_id', str(f.owners[other])))
                visible = db.execute(sql.SQL('SELECT owner_id FROM {}').format(table)).fetchall()
                self.assertEqual([r[0] for r in visible], [f.owners[i]])
                mapping = db.execute(sql.SQL('SELECT owner_id FROM {}.tenant_logins')
                                     .format(sql.Identifier(f.schema))).fetchall()
                self.assertEqual([r[0] for r in mapping], [f.owners[i]])

    def test_cross_owner_write_rejected_and_mapping_read_only(self):
        from psycopg import sql
        f = self.fixture
        table = sql.SQL('{}.tenant_events').format(sql.Identifier(f.schema))
        with self.pg.connect(tenant_dsn(ADMIN, f, 0)) as db:
            with self.assertRaises(self.pg.Error):
                db.execute(sql.SQL('INSERT INTO {} (id,owner_id,summary) VALUES (%s,%s,%s)')
                           .format(table), (uuid.uuid4(), f.owners[1], 'forbidden'))
            db.rollback()
            with self.assertRaises(self.pg.Error):
                db.execute(sql.SQL('UPDATE {}.tenant_logins SET owner_id=%s')
                           .format(sql.Identifier(f.schema)), (f.owners[1],))
            db.rollback()
            with self.assertRaises(self.pg.Error):
                db.execute(sql.SQL('SET ROLE {}').format(sql.Identifier(f.roles[1])))
            db.rollback()

    def test_shared_runtime_has_no_access_to_isolated_schema(self):
        from psycopg import sql
        runtime = os.environ['CYBERSENTINEL_TEST_PG_RUNTIME_DSN']
        if not disposable_test_dsn(runtime):
            self.fail('Runtime DSN must point to the disposable CI service')
        with self.pg.connect(runtime) as db:
            with self.assertRaises(self.pg.Error):
                db.execute(sql.SQL('SELECT count(*) FROM {}.tenant_events')
                           .format(sql.Identifier(self.fixture.schema)))
            db.rollback()


if __name__ == '__main__':
    unittest.main()
