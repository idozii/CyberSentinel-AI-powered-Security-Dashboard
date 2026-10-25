"""Real role-scoped DB adapter. Only runs in isolated GitHub PostgreSQL 17."""
from __future__ import annotations

import os
import unittest

from scripts.step39_actor_boundary import disposable_test_dsn
from scripts.step41_role_boundary import (delete_disposable, install_disposable,
                                         make_fixture, protected_ci)
from scripts.step42_isolated_repository import IsolatedTenantRepository

ADMIN = os.getenv('CYBERSENTINEL_TEST_PG_ADMIN_DSN', '')
ISOLATED = (
    os.getenv('GITHUB_ACTIONS') == 'true'
    and os.getenv('CYBERSENTINEL_ISOLATED_PG_CI') == '1'
    and ADMIN.startswith('postgresql://postgres:ci-ephemeral-admin@127.0.0.1:5432/')
    and disposable_test_dsn(ADMIN)
)


@unittest.skipUnless(ISOLATED, 'Only isolated PostgreSQL 17 GitHub CI')
class TenantRepositoryPg(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        protected_ci(ADMIN)
        cls.fixture = make_fixture()
        install_disposable(ADMIN, cls.fixture)

    @classmethod
    def tearDownClass(cls):
        delete_disposable(ADMIN, cls.fixture)

    def test_two_roles_crud_without_cross_tenant_leakage(self):
        a = IsolatedTenantRepository(ADMIN, self.fixture, 0)
        b = IsolatedTenantRepository(ADMIN, self.fixture, 1)
        self.assertEqual(a.list_summaries(), ['tenant-0'])
        self.assertEqual(b.list_summaries(), ['tenant-1'])
        self.assertEqual(a.add_synthetic_summary('role-a'), ['role-a', 'tenant-0'])
        self.assertEqual(b.list_summaries(), ['tenant-1'])
        self.assertEqual(b.add_synthetic_summary('role-b'), ['role-b', 'tenant-1'])
        self.assertEqual(a.list_summaries(), ['role-a', 'tenant-0'])

    def test_invalid_summary_fails_without_changing_other_tenant(self):
        a = IsolatedTenantRepository(ADMIN, self.fixture, 0)
        b = IsolatedTenantRepository(ADMIN, self.fixture, 1)
        before = b.list_summaries()
        with self.assertRaises(ValueError):
            a.add_synthetic_summary('x' * 500)
        self.assertEqual(b.list_summaries(), before)


if __name__ == '__main__':
    unittest.main()
