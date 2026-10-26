"""Local-only regression; no network, database, external credentials or browser."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.install_portfolio_finalizer import CI_ANCHOR, CI_BLOCK, README_ANCHOR, README_BLOCK, install
from scripts.portfolio_finalizer import ROOT, evaluate, export_pack, render_files


class PortfolioFinalizerTests(unittest.TestCase):
    def test_final_source_gate_reconciles_recorded_metrics(self):
        report = evaluate()
        self.assertEqual(report['status'], 'automated_pass', report)
        self.assertTrue(all(report['checks'].values()), report)
        self.assertEqual(report['metrics']['simulated_requests'], 2678)
        self.assertEqual(report['metrics']['isolation_forest_fn'], 17)
        self.assertEqual(report['metrics']['scan_detected'], 0)
        self.assertFalse(report['portfolio_100_percent_certified_by_script'])
        self.assertFalse(report['production_saas_ready'])
        self.assertFalse(report['cloud_database_or_auth0_required'])

    def test_emphasis_is_on_weak_recall_not_100_percent_ml_accuracy(self):
        report = evaluate()
        docs = render_files(report)
        fact = docs['FACT_SHEET.md']
        self.assertIn('7/24 (29.17% recall)', fact)
        self.assertIn('17', fact)
        self.assertIn('0/8', fact)
        self.assertIn('not generalized performance', fact)
        self.assertNotIn('production-grade', fact)
        self.assertIn('team repository', docs['CV_INTERVIEW.md'])

    def test_evidence_pack_is_standalone_and_never_overwrites(self):
        report = evaluate()
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / 'handoff'
            export_pack(dest, report)
            names = sorted(p.name for p in dest.iterdir())
            self.assertEqual(names, ['CV_INTERVIEW.md', 'DEMO_SCRIPT.md', 'EVIDENCE.json',
                                     'FACT_SHEET.md', 'RELEASE_CHECKLIST.md'])
            content = json.loads((dest / 'EVIDENCE.json').read_text())
            self.assertEqual(content['status'], 'automated_pass')
            self.assertEqual(len(content['evidence_sha256']['dashboard/public_metrics.json']), 64)
            with self.assertRaises(FileExistsError):
                export_pack(dest, report)
            self.assertNotIn('postgresql://', str(content))

    def test_export_refuses_repository_and_unvalidated_pack(self):
        with self.assertRaises(ValueError):
            export_pack(ROOT / 'temporary-recruiter-bundle', evaluate())
        broken = {**evaluate(), 'status': 'blocked'}
        with self.assertRaises(RuntimeError), tempfile.TemporaryDirectory() as td:
            export_pack(Path(td) / 'new-folder', broken)

    def test_tampered_metrics_fail_gate(self):
        import shutil
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name in ('dashboard/public_metrics.json', 'dashboard/public_data.py'):
                p = root / name
                p.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, p)
            (root / 'dashboard/public_metrics.json').write_text('{"schema_version":"fake"}')
            report = evaluate(root)
            self.assertEqual(report['status'], 'blocked')
            self.assertFalse(report['checks']['holdout_numbers_reconciled'])

    def test_installer_adds_only_two_files_is_repeatable(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workflow = root / '.github/workflows/ci.yml'
            workflow.parent.mkdir(parents=True)
            workflow.write_text('name: CI\ntest_zero_cost_portfolio.py -v\n' + CI_ANCHOR)
            readme = root / 'README.md'
            readme.write_text(README_ANCHOR + 'Original document\n')
            original = (workflow.read_text(), readme.read_text())
            self.assertEqual(len(install(root, check_only=True)), 2)
            self.assertEqual(original, (workflow.read_text(), readme.read_text()))
            self.assertEqual(len(install(root)), 2)
            self.assertEqual(install(root), [])
            self.assertIn(CI_BLOCK, workflow.read_text())
            self.assertIn(README_BLOCK, readme.read_text())
            self.assertTrue(readme.read_text().endswith('Original document\n'))

    def test_installer_rejects_missing_anchors_without_edit(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workflow = root / '.github/workflows/ci.yml'
            workflow.parent.mkdir(parents=True)
            workflow.write_text('name: unknown\n')
            readme = root / 'README.md'
            readme.write_text(README_ANCHOR)
            with self.assertRaises(RuntimeError):
                install(root)
            self.assertEqual(workflow.read_text(), 'name: unknown\n')

    def test_manual_items_are_not_silently_accepted(self):
        report = evaluate()
        self.assertEqual(len(report['manual_acceptance_pending']), 5)
        self.assertFalse(report['portfolio_100_percent_certified_by_script'])
        checklist = render_files(report)['RELEASE_CHECKLIST.md']
        self.assertIn('Human evidence', checklist)
        self.assertIn('Fresh clone', checklist)
        self.assertIn('real demonstration', checklist)


if __name__ == '__main__':
    unittest.main()
