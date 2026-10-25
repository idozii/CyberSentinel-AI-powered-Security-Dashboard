"""Step 39-40 regression: no cloud contact, no credential disclosure, beta blocked."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.install_step39_40 import CI_PG_ANCHOR, CI_UNIT_ANCHOR, install
from scripts.step39_actor_boundary import audit
from scripts.step39_40_preflight import check
from scripts.step39_40_release import rehearse
from scripts.step40_readiness_report import _save_create_only, readiness
from scripts.step39_actor_boundary import disposable_test_dsn


class SafeReadiness(unittest.TestCase):
    def test_mutable_guc_is_recognized_as_unresolved_critical_boundary(self):
        result = audit()
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['finding'], 'shared_runtime_role_mutable_actor_id')
        self.assertFalse(result['credential_compromise_isolation_proven'])
        self.assertFalse(result['public_beta_allowed'])
        self.assertEqual(len(result['checks']), 5)
        self.assertTrue(all(result['checks'].values()))

    def test_readiness_is_explicit_no_go_without_real_evidence(self):
        report = readiness()
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['beta_gate'], 'blocked')
        self.assertFalse(report['public_beta_allowed'])
        self.assertTrue(report['actor_boundary_review_required'])
        self.assertEqual(len(report['remaining_external_conditions']), 12)
        body = json.dumps(report)
        self.assertNotIn('postgresql://', body)
        self.assertNotIn('csp_', body)

    def test_output_create_only_private_permissions_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'report.json'
            _save_create_only(p, readiness())
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(p.read_text())['status'], 'blocked')
            with self.assertRaises(FileExistsError):
                _save_create_only(p, readiness())
            symlink = Path(temp) / 'redirect.json'
            symlink.symlink_to(p)
            with self.assertRaises(FileExistsError):
                _save_create_only(symlink, readiness())

    def test_audit_does_not_allow_arbitrary_test_db_locations(self):
        self.assertTrue(disposable_test_dsn('postgresql://tester:safe@127.0.0.1:5432/cybersentinel_stage'))
        self.assertFalse(disposable_test_dsn('postgresql://tester:safe@example.com:5432/cybersentinel_stage'))
        self.assertFalse(disposable_test_dsn('postgresql://tester:safe@127.0.0.1:5432/production'))
        self.assertFalse(disposable_test_dsn('postgresql://tester:safe@127.0.0.1:5432/cybersentinel_stage#x'))

    def test_idempotent_installer_in_sandbox(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)
            (p/'.github/workflows').mkdir(parents=True)
            target = p/'.github/workflows/ci.yml'
            target.write_text('jobs:\n'+CI_PG_ANCHOR+CI_UNIT_ANCHOR)
            (p/'README.md').write_text('# CyberSentinel\n')
            first = install(p)
            second = install(p)
            self.assertTrue(all(first.values()))
            self.assertFalse(any(second.values()))
            ci = target.read_text()
            self.assertEqual(ci.count('test_step39_actor_spoof_pg.py -v'), 1)
            self.assertEqual(ci.count('python -m scripts.step39_40_release'), 1)

    def test_preflight_and_release_keep_beta_blocked(self):
        self.assertEqual(check()['status'], 'pass')
        report = rehearse()
        self.assertEqual(report['status'], 'pass', str(report))
        self.assertEqual(report['beta_gate'], 'blocked')
        self.assertFalse(report['authorization_to_deploy_publicly'])


if __name__ == '__main__':
    unittest.main()
