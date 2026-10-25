"""Offline regression for Step 41 psycopg bug, CI-only adapter and no-go gate."""
from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

from scripts.step41_role_boundary import make_fixture, protected_ci
from scripts.step42_isolated_repository import IsolatedTenantRepository
from scripts.step42_43_preflight import check
from scripts.step42_43_release import rehearse
from scripts.step43_migration_plan import assess


class IsolatedPrototypeOffline(unittest.TestCase):
    def test_cursor_executemany_fix_and_ci_configuration(self):
        report = check()
        self.assertEqual(report['status'], 'pass', report)
        self.assertTrue(all(report['checks'].values()))

    def test_repo_rejects_non_ci_dsn_and_invalid_fixture(self):
        f = make_fixture()
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false',
                                      'CYBERSENTINEL_ISOLATED_PG_CI': '0'}):
            for dsn in ('postgresql://postgres:pass@127.0.0.1:5432/cybersentinel_stage',
                        'postgresql://cybersentinel_runtime:pass@database.neon.tech/db'):
                with self.subTest(dsn=dsn), self.assertRaises(RuntimeError):
                    IsolatedTenantRepository(dsn, f, 0)
        with self.assertRaises(RuntimeError):
            protected_ci('postgresql://postgres:pass@database.neon.tech/db')

    def test_migration_plan_explicitly_not_production(self):
        plan = assess()
        self.assertEqual(plan['status'], 'blocked_for_public_beta')
        self.assertTrue(plan['checks']['existing_cs_tables_not_migrated'])
        self.assertTrue(plan['checks']['shared_runtime_actor_guc_still_in_use'])
        self.assertEqual(len(plan['phases']), 6)
        self.assertNotIn('password', json.dumps(plan).lower())

    def test_release_does_not_change_neon(self):
        result = rehearse()
        self.assertEqual(result['status'], 'pass', result)
        self.assertFalse(result['staging_migrated'])
        self.assertEqual(result['public_beta'], 'blocked')


if __name__ == '__main__':
    unittest.main()
