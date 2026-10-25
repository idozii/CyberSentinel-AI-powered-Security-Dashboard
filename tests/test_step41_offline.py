"""Step 41 offline invariants. Works without PostgreSQL or network access."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.install_step41 import install
from scripts.step41_role_boundary import (assessment, make_fixture, protected_ci)
from scripts.step41_preflight import check
from scripts.step41_release import rehearse


class Step41Offline(unittest.TestCase):
    def test_prototype_guard_rejects_local_and_remote_without_ci(self):
        for dsn in ('postgresql://admin:pass@127.0.0.1:5432/cybersentinel_stage',
                    'postgresql://admin:pass@db.neon.tech/production'):
            with self.subTest(dsn=dsn), patch.dict(os.environ, {
                'GITHUB_ACTIONS': 'false', 'CYBERSENTINEL_ISOLATED_PG_CI': '0'}):
                with self.assertRaises(RuntimeError):
                    protected_ci(dsn)

    def test_role_credentials_random_and_not_exposed_in_assessment(self):
        a, b = make_fixture(), make_fixture()
        self.assertNotEqual(a.schema, b.schema)
        self.assertNotEqual(a.roles, b.roles)
        self.assertNotEqual(a.passwords, b.passwords)
        self.assertFalse(assessment()['supports_public_deployment'])
        self.assertNotIn(a.passwords[0], json.dumps(assessment()))

    def test_install_repeatable_and_preserves_existing_content(self):
        from scripts.install_step41 import PG_ANCHOR, UNIT_ANCHOR
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root/'.github/workflows').mkdir(parents=True)
            (root/'.github/workflows/ci.yml').write_text(PG_ANCHOR+UNIT_ANCHOR)
            (root/'README.md').write_text('Original README\n')
            self.assertEqual(install(root), {'ci_changed': True, 'readme_changed': True})
            old = (root/'.github/workflows/ci.yml').read_text()
            self.assertEqual(install(root), {'ci_changed': False, 'readme_changed': False})
            self.assertEqual((root/'.github/workflows/ci.yml').read_text(), old)
            self.assertTrue((root/'README.md').read_text().startswith('Original README\n'))

    def test_preflight_and_beta_gate_fail_closed(self):
        self.assertEqual(check()['status'], 'pass')
        r = rehearse()
        self.assertEqual(r['status'], 'pass')
        self.assertEqual(r['public_beta'], 'blocked')
        self.assertTrue(all(r['checks'].values()))


if __name__ == '__main__':
    unittest.main()
