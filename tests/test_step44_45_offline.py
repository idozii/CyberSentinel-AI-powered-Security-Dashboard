"""Offline regression: protective guards, CI installer, public beta no-go."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.install_step44_45 import install, PG_ANCHOR, UNIT_ANCHOR
from scripts.step41_role_boundary import make_fixture
from scripts.step44_tenant_lifecycle import DisposableTenantLifecycle
from scripts.step45_security_gate import assess


class Step44_45Offline(unittest.TestCase):
    def test_never_accepts_local_or_remote_dsn_outside_ci(self):
        fixture = make_fixture()
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false',
                                      'CYBERSENTINEL_ISOLATED_PG_CI': '0'}):
            for dsn in ('postgresql://postgres:ci-ephemeral-admin@127.0.0.1:5432/cybersentinel_stage',
                        'postgresql://postgres:ci-ephemeral-admin@neon.example/cybersentinel_stage'):
                with self.subTest(dsn=dsn), self.assertRaises(RuntimeError):
                    DisposableTenantLifecycle(dsn, fixture)

    def test_rejects_bad_fixture_and_index_even_with_stubbed_ci_guard(self):
        from dataclasses import replace
        fixture = make_fixture()
        with patch('scripts.step44_tenant_lifecycle.protected_ci'):
            good = DisposableTenantLifecycle('non-operational', fixture)
            with self.assertRaises(ValueError):
                good._role(-1)
            with self.assertRaises(ValueError):
                good._role(2)
            with self.assertRaises(ValueError):
                DisposableTenantLifecycle('non-operational', replace(fixture, schema='cs'))
            with self.assertRaises(ValueError):
                DisposableTenantLifecycle('non-operational', replace(fixture, roles=('a', 'b')))

    def test_installer_is_idempotent_and_preserves_workflow(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / '.github/workflows/ci.yml'
            path.parent.mkdir(parents=True)
            initial = ('name: Dummy CI\n'
                       'test_step42_43_offline.py -v\n'
                       'test_step42_43_pg.py -v\n'
                       + UNIT_ANCHOR + PG_ANCHOR + 'end: true\n')
            path.write_text(initial, encoding='utf-8')
            self.assertTrue(install(root))
            after = path.read_text(encoding='utf-8')
            self.assertFalse(install(root))
            self.assertFalse(install(root, check_only=True))
            self.assertEqual(after, path.read_text(encoding='utf-8'))
            self.assertTrue(after.startswith('name: Dummy CI\n'))
            self.assertTrue(after.endswith('end: true\n'))
            self.assertEqual(after.count('test_step44_45_pg.py -v'), 1)
            self.assertEqual(after.count('test_step44_45_offline.py -v'), 1)

    def test_read_only_gate_keeps_public_beta_blocked(self):
        report = assess()
        self.assertEqual(report['status'], 'ready_for_ci_review', report)
        self.assertTrue(all(report['checks'].values()), report)
        self.assertFalse(report['public_beta_allowed'])
        self.assertFalse(report['staging_migrated'])
        self.assertFalse(report['credential_broker_implemented'])
        self.assertFalse(report['existing_session_revocation_proven'])


if __name__ == '__main__':
    unittest.main()
