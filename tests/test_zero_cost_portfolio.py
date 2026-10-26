"""No-remote-traffic regression for the zero-budget portfolio release."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.install_zero_cost_portfolio import (BUTTON_ANCHOR, CI_ANCHOR, NAV_ANCHOR,
                                                  PAGE_ANCHOR, README_ANCHOR, install)
from scripts.zero_cost_portfolio import (ROOT, assess, demo_command, read_evidence,
                                          render_html, scrubbed_environment, write_output)


class ZeroCostPortfolioTests(unittest.TestCase):
    def test_committed_aggregate_metrics_are_consistent_and_have_known_limitations(self):
        data = read_evidence()
        self.assertEqual(data['source']['simulated_requests'], 2678)
        self.assertEqual(data['source']['feature_windows'], 160)
        self.assertEqual(data['test']['isolation_forest']['fn'], 17)
        self.assertEqual(data['test']['attack_scenarios']['Path scanning']['detected'], 0)

    def test_offline_static_audit_is_no_go_for_public_saas(self):
        report = assess()
        self.assertEqual(report['status'], 'pass', report)
        self.assertFalse(report['managed_database_required'])
        self.assertFalse(report['auth0_required'])
        self.assertFalse(report['production_saas_ready'])
        self.assertFalse(report['public_multi_tenant_beta_allowed'])
        self.assertNotIn('in_process_mvp_smoke', report['checks'])

    def test_launcher_must_use_loopback_and_never_select_public_host(self):
        command = demo_command(8501)
        self.assertIn('127.0.0.1', command)
        self.assertNotIn('0.0.0.0', command)
        self.assertIn('false', command)
        with self.assertRaises(ValueError):
            demo_command(80)
        with self.assertRaises(ValueError):
            demo_command(True)

    def test_cloud_secrets_are_not_inherited_by_demo_process(self):
        with patch.dict(os.environ, {'DATABASE_URL': 'sensitive',
                                      'AUTH0_CLIENT_SECRET': 'sensitive',
                                      'CYBERSENTINEL_PG_RUNTIME_DSN': 'sensitive',
                                      'CYBERSENTINEL_AGENT_KEY': 'sensitive',
                                      'NEON_DATABASE_URL': 'sensitive'}):
            values = scrubbed_environment()
        self.assertEqual(values['CYBERSENTINEL_OFFLINE_ONLY'], '1')
        self.assertEqual(values['STREAMLIT_BROWSER_GATHER_USAGE_STATS'], 'false')
        self.assertFalse(any('sensitive' == v for v in values.values()))
        self.assertNotIn('DATABASE_URL', values)

    def test_html_report_is_self_contained_and_does_not_claim_live_accuracy(self):
        body = render_html(assess())
        self.assertIn('Missed attacks', body)
        self.assertIn('29.2%', body)
        self.assertIn('NO-GO', body)
        self.assertNotIn('<script', body)
        self.assertNotIn('https://', body)

    def test_rejects_writes_inside_repository_and_refuses_overwrite(self):
        report = assess()
        with self.assertRaises(ValueError):
            write_output(ROOT / 'simulations/runtime/processed/leak.html', report)
        with tempfile.TemporaryDirectory() as td:
            destination = Path(td) / 'evidence.html'
            write_output(destination, report)
            self.assertTrue(destination.read_text().startswith('<!doctype html>'))
            with self.assertRaises(FileExistsError):
                write_output(destination, report)
            destination_json = Path(td) / 'evidence.json'
            write_output(destination_json, report)
            self.assertEqual(json.loads(destination_json.read_text())['status'], 'pass')

    def test_installer_is_additive_idempotent_and_check_only_does_not_write(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root/'dashboard').mkdir()
            (root/'.github/workflows').mkdir(parents=True)
            app = root/'dashboard/public_app.py'
            app.write_text('import time\n'+NAV_ANCHOR+BUTTON_ANCHOR+'\n'+PAGE_ANCHOR+'\n')
            ci = root/'.github/workflows/ci.yml'
            ci.write_text('name: CI\ntest_step58_63_offline.py -v\n'+CI_ANCHOR)
            readme = root/'README.md'
            readme.write_text(README_ANCHOR+'\nOriginal content\n')
            before = [x.read_text() for x in (app, ci, readme)]
            self.assertEqual(len(install(root, check_only=True)), 3)
            self.assertEqual(before, [x.read_text() for x in (app, ci, readme)])
            self.assertEqual(len(install(root)), 3)
            self.assertEqual(install(root), [])
            after = [x.read_text() for x in (app, ci, readme)]
            self.assertIn('disabled=OFFLINE_ONLY', after[0])
            self.assertIn('test_zero_cost_portfolio.py', after[1])
            self.assertIn('Zero-Cost Portfolio Release', after[2])
            self.assertEqual(install(root, check_only=True), [])

    def test_installer_rejects_unexpected_sources_without_modification(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root/'dashboard').mkdir()
            (root/'.github/workflows').mkdir(parents=True)
            (root/'dashboard/public_app.py').write_text('unsafe rewrite')
            (root/'.github/workflows/ci.yml').write_text(CI_ANCHOR)
            (root/'README.md').write_text(README_ANCHOR)
            with self.assertRaises(RuntimeError):
                install(root)
            self.assertEqual((root/'dashboard/public_app.py').read_text(), 'unsafe rewrite')

    def test_audit_rejects_tampered_public_metrics_without_exposing_data(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root/'dashboard').mkdir()
            (root/'dashboard/public_metrics.json').write_text('{}')
            (root/'dashboard/public_app.py').write_text('')
            result = assess(root)
            self.assertEqual(result['status'], 'blocked')
            self.assertFalse(result['checks']['aggregate_evidence_validated'])


if __name__ == '__main__':
    unittest.main()
