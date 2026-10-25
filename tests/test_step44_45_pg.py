"""Real PostgreSQL 17: disposable role privileges, rotate and disable logins.

Runs ONLY in GitHub CI with the disposable Postgres service. Skipped locally.
"""
from __future__ import annotations

import os
import unittest

from scripts.step39_actor_boundary import disposable_test_dsn
from scripts.step41_role_boundary import (delete_disposable, install_disposable,
                                         make_fixture, protected_ci, tenant_dsn)
from scripts.step44_tenant_lifecycle import DisposableTenantLifecycle

ADMIN = os.getenv('CYBERSENTINEL_TEST_PG_ADMIN_DSN', '')
ENABLED = (os.getenv('GITHUB_ACTIONS') == 'true'
           and os.getenv('CYBERSENTINEL_ISOLATED_PG_CI') == '1'
           and ADMIN.startswith('postgresql://postgres:ci-ephemeral-admin@127.0.0.1:5432/')
           and disposable_test_dsn(ADMIN))


@unittest.skipUnless(ENABLED, 'Step 44-45 requires disposable PostgreSQL CI')
class DisposableRoleLifecyclePg(unittest.TestCase):
    def setUp(self):
        import psycopg
        self.pg = psycopg
        protected_ci(ADMIN)
        self.fixture = make_fixture()
        install_disposable(ADMIN, self.fixture)
        self.lifecycle = DisposableTenantLifecycle(ADMIN, self.fixture)

    def tearDown(self):
        delete_disposable(ADMIN, self.fixture)

    def test_roles_have_least_privileges(self):
        for index in (0, 1):
            state = self.lifecycle.role_state(index)
            self.assertTrue(state['can_login'])
            for key in ('superuser', 'bypass_rls', 'create_role',
                        'create_db', 'replication', 'inherits_roles'):
                self.assertFalse(state[key], (index, key, state))
            grants = self.lifecycle.privilege_state(index)
            self.assertTrue(grants['schema_usage'])
            self.assertTrue(grants['mapping_select'])
            self.assertTrue(grants['events_insert'])
            self.assertFalse(grants['schema_create'])
            self.assertFalse(grants['mapping_update'])
            self.assertFalse(grants['member_of_other_tenant'])

    def test_rotation_rejects_old_password_without_affecting_other_tenant(self):
        from psycopg.conninfo import make_conninfo
        old_dsn = tenant_dsn(ADMIN, self.fixture, 0)
        new_password = self.lifecycle.rotate_password(0)
        self.assertGreaterEqual(len(new_password), 48)
        with self.assertRaises(self.pg.OperationalError):
            self.pg.connect(old_dsn, connect_timeout=4)
        with self.pg.connect(make_conninfo(ADMIN, user=self.fixture.roles[0],
                                          password=new_password)) as conn:
            self.assertEqual(conn.execute('SELECT session_user').fetchone()[0],
                             self.fixture.roles[0])
        with self.pg.connect(tenant_dsn(ADMIN, self.fixture, 1)) as conn:
            self.assertEqual(conn.execute('SELECT session_user').fetchone()[0],
                             self.fixture.roles[1])

    def test_disable_blocks_new_logins_without_affecting_other_tenant(self):
        self.lifecycle.disable_login(0)
        self.assertFalse(self.lifecycle.role_state(0)['can_login'])
        with self.assertRaises(self.pg.OperationalError):
            self.pg.connect(tenant_dsn(ADMIN, self.fixture, 0), connect_timeout=4)
        with self.pg.connect(tenant_dsn(ADMIN, self.fixture, 1)) as conn:
            self.assertEqual(conn.execute('SELECT session_user').fetchone()[0],
                             self.fixture.roles[1])


if __name__ == '__main__':
    unittest.main()
