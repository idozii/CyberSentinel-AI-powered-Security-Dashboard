"""Step 21 safety and reproducibility for synthetic threshold sweeps."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from hosted_api.demo_tuning import (PINNED_MANIFEST_SHA256, _baseline,
                                    _partition_scores, quality_gate, run_shadow_experiment)
from hosted_api.demo_evaluation import SCENARIOS
from hosted_api.local_demo import DemoStore, create_demo_app
from owner_api.detection import RULES
from scripts.step21_quality_gate import run


class Step21TuningTest(unittest.TestCase):
    def test_regression_gate_and_pinned_baseline(self):
        result = quality_gate()
        self.assertEqual(result['status'], 'pass', result['checks'])
        self.assertTrue(all(result['checks'].values()))
        report = result['experiment']
        self.assertEqual(report['source_manifest_sha256'], PINNED_MANIFEST_SHA256)
        self.assertEqual(report['candidate_count'], 81)
        self.assertEqual(report['baseline_full_metrics']['tp'], 4)
        self.assertEqual(report['baseline_full_metrics']['fp'], 2)
        self.assertEqual(report['baseline_full_metrics']['fn'], 2)
        self.assertEqual(report['baseline_full_metrics']['tn'], 48)
        self.assertFalse(report['live_config_changed'])
        self.assertFalse(report['release_approved'])

    def test_development_improvement_overfits_frozen_holdout(self):
        result = run_shadow_experiment()
        self.assertEqual(len(result['development_scenarios']), 8)
        self.assertEqual(len(result['validation_scenarios']), 6)
        self.assertEqual(result['baseline_development']['metrics']['f1'], 0.6667)
        self.assertEqual(result['candidate_development']['metrics']['f1'], 1.0)
        self.assertEqual(result['baseline_validation']['metrics']['f1'], 0.6667)
        self.assertEqual(result['candidate_validation']['metrics']['f1'], 0.3333)
        self.assertEqual(result['candidate_thresholds']['repeated_login_failures'], 4)
        self.assertEqual(result['candidate_thresholds']['http_404_burst'], 9)
        self.assertEqual(result['validation_f1_delta'], -0.3334)
        self.assertEqual(result['baseline_thresholds'], _baseline())

    def test_candidate_sweep_is_repeatable(self):
        a = run_shadow_experiment()
        b = run_shadow_experiment()
        self.assertEqual(a, b)
        self.assertEqual(len(a['experiment_sha256']), 64)
        self.assertNotIn('csp_', json.dumps(a))
        self.assertNotIn('csd_', json.dumps(a))
        self.assertNotIn('postgresql://', json.dumps(a))

    def test_rule_thresholds_never_changed(self):
        before = tuple(RULES)
        run_shadow_experiment()
        self.assertEqual(tuple(RULES), before)
        self.assertEqual(_baseline()['repeated_login_failures'], 5)
        self.assertEqual(_baseline()['http_404_burst'], 8)
        self.assertEqual(_baseline()['server_error_burst'], 5)
        self.assertEqual(_baseline()['request_volume_spike'], 40)

    def test_manifest_guard_detects_unreviewed_changes(self):
        with patch('hosted_api.demo_tuning.PINNED_MANIFEST_SHA256', '0'*64):
            self.assertEqual(quality_gate()['status'], 'fail')

    def test_candidate_scores_sum_all_rule_pairs(self):
        metrics = _partition_scores(SCENARIOS[:3], _baseline())['metrics']
        self.assertEqual(sum(metrics[k] for k in ('tp','fp','fn','tn')), 3 * len(RULES))

    def test_report_files_created_securely_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'step21-report'
            result = run(target)
            self.assertEqual(result['status'], 'pass')
            self.assertEqual(target.stat().st_mode & 0o777, 0o700)
            for name in ('step21_tuning.json','step21_tuning.md'):
                f = target / name
                self.assertTrue(f.is_file())
                self.assertEqual(f.stat().st_mode & 0o777, 0o600)
            data = json.loads((target / 'step21_tuning.json').read_text())
            self.assertEqual(data['candidate_validation']['metrics']['f1'], 0.3333)
            self.assertIn('Offline Threshold Sensitivity', (target/'step21_tuning.md').read_text())
            with self.assertRaises(FileExistsError):
                run(target)
        with self.assertRaisesRegex(ValueError, 'outside'):
            run(Path(__file__).resolve().parents[1] / 'step21-report')

    def test_evaluation_page_is_read_only(self):
        demo = DemoStore()
        token = demo.issue_key()
        snapshot = demo.snapshot()
        client = TestClient(create_demo_app(store=demo,enabled=True))
        response = client.get('/demo/tuning')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Synthetic threshold sensitivity', response.text)
        self.assertIn('100.0%', response.text)
        self.assertIn('33.33%', response.text)
        self.assertNotIn(token, response.text)
        self.assertNotIn(demo._token_hash, response.text)
        self.assertEqual(demo.snapshot(), snapshot)
        self.assertIn('/demo/tuning', client.get('/').text)

    def test_never_needs_neon_or_auth0(self):
        with patch.dict(os.environ, {
            'CYBERSENTINEL_PG_RUNTIME_DSN': 'intentionally-not-a-real-dsn',
            'CYBERSENTINEL_AUTH0_CLIENT_SECRET': 'intentionally-incorrect',
        }):
            self.assertEqual(quality_gate()['status'], 'pass')


if __name__ == '__main__':
    unittest.main()
