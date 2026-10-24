"""Step 20 synthetic benchmark reproducibility, confusion matrix and isolation."""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from hosted_api.demo_evaluation import SCENARIOS, Scenario, evaluate, markdown_report
from hosted_api.local_demo import DemoStore, create_demo_app
from scripts.step20_evaluate import run


class EvaluationTest(unittest.TestCase):
    def test_fixture_counts_and_known_failure_modes(self):
        report = evaluate()
        self.assertEqual(report['scenario_count'], 14)
        self.assertEqual(report['rule_count'], 4)
        self.assertEqual(report['scenario_rule_pairs'], 56)
        self.assertEqual(report['metrics'], {
            'tp': 4, 'fp': 2, 'fn': 2, 'tn': 48,
            'precision': 0.6667, 'recall': 0.6667, 'f1': 0.6667})
        rows = {r['scenario']: r for r in report['scenarios']}
        self.assertEqual(rows['login_failures']['detected_rules'], ['repeated_login_failures'])
        self.assertEqual(rows['traffic_spike']['detected_rules'], ['request_volume_spike'])
        self.assertEqual(rows['benign_missing_links']['false_positive_rules'], ['http_404_burst'])
        self.assertEqual(rows['benign_health_polling']['false_positive_rules'], ['request_volume_spike'])
        self.assertEqual(rows['low_rate_login_attempts']['false_negative_rules'], ['repeated_login_failures'])
        self.assertEqual(rows['slow_path_probe']['false_negative_rules'], ['http_404_burst'])
        self.assertEqual(rows['split_login_sources']['detected_rules'], [])
        self.assertEqual(rows['split_5xx_sources']['detected_rules'], [])
        self.assertEqual(report['total_synthetic_events'], report['replayed_duplicates'])
        self.assertNotIn('csd_', json.dumps(report))
        self.assertNotIn('postgresql://', json.dumps(report))

    def test_repeat_runs_same_scores_and_manifest(self):
        t = float(int(time.time()))
        a = evaluate(clock=t)
        b = evaluate(clock=t)
        self.assertEqual(a, b)
        self.assertEqual(len(a['manifest_sha256']), 64)
        self.assertIn('not a real-world attack dataset', a['limitations'][0])

    def test_each_rule_pair_counted_once(self):
        result = evaluate()
        for metric in result['per_rule'].values():
            self.assertEqual(sum(metric[x] for x in ('tp','fp','fn','tn')), len(SCENARIOS))
        for key in ('tp','fp','fn','tn'):
            self.assertEqual(sum(r[key] for r in result['per_rule'].values()), result['metrics'][key])

    def test_manifest_validation(self):
        with self.assertRaisesRegex(ValueError, 'unknown expected rule'):
            evaluate(scenarios=(Scenario('bogus', 1, 'health', 200, ('fake_rule',)),))
        with self.assertRaisesRegex(ValueError, 'Duplicate scenario'):
            evaluate(scenarios=(SCENARIOS[0], SCENARIOS[0]))
        with self.assertRaisesRegex(ValueError, 'source split'):
            evaluate(scenarios=(Scenario('bad_split', 5, 'login', 401, source_split=(2,2)),))

    def test_report_written_only_to_new_external_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'result'
            report = run(dest)
            json_path = dest / 'step20_evaluation.json'
            md_path = dest / 'step20_evaluation.md'
            self.assertTrue(json_path.exists())
            self.assertTrue(md_path.exists())
            self.assertEqual(json.loads(json_path.read_text())['metrics'], report['metrics'])
            text = md_path.read_text()
            self.assertIn('## Micro-aggregated confusion matrix', text)
            self.assertIn('## Limitations', text)
            self.assertIn('benign_missing_links', text)
            self.assertNotIn('csd_', text)
            self.assertEqual(dest.stat().st_mode & 0o777, 0o700)
            for output in (json_path, md_path):
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                run(dest)
        with self.assertRaisesRegex(ValueError, 'outside'):
            run(Path(__file__).resolve().parents[1] / 'step20-report')

    def test_markdown_handles_empty_prediction_denominators(self):
        doc = markdown_report(evaluate(scenarios=(SCENARIOS[4],)))
        self.assertIn('N/A', doc)
        self.assertNotIn('nan', doc)

    def test_dashboard_evaluation_does_not_mutate_demo_key_or_events(self):
        store = DemoStore()
        key = store.issue_key()
        before = store.snapshot()
        app = create_demo_app(store=store, enabled=True)
        client = TestClient(app)
        evaluation_page = client.get('/demo/evaluation')
        self.assertEqual(evaluation_page.status_code, 200)
        self.assertIn('Synthetic detection evaluation', evaluation_page.text)
        self.assertIn('False alarms', evaluation_page.text.replace('false alarms', 'False alarms'))
        self.assertIn('66.67%', evaluation_page.text)
        self.assertIn('benign_missing_links', evaluation_page.text)
        self.assertEqual(store.snapshot(), before)
        self.assertNotIn(key, evaluation_page.text)
        self.assertNotIn(store._token_hash, evaluation_page.text)
        dashboard = client.get('/')
        self.assertIn('href="/demo/evaluation"', dashboard.text)
        self.assertEqual(client.get('/docs').status_code, 404)

    def test_evaluation_does_not_require_db_or_auth0(self):
        with patch.dict(os.environ, {
            'CYBERSENTINEL_PG_RUNTIME_DSN': 'intentionally-invalid',
            'CYBERSENTINEL_AUTH0_CLIENT_SECRET': 'intentionally-invalid',
        }):
            report = evaluate()
            self.assertEqual(report['metrics']['tp'], 4)


if __name__ == '__main__':
    unittest.main()
