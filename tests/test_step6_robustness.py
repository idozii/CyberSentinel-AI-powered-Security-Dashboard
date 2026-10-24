"""Step 6: frozen-model audit, counterfactual invariants and fail-closed checks."""
from __future__ import annotations

import copy
import csv
import json
import tempfile
import unittest
from pathlib import Path

from scripts.audit_detector_robustness import (
    audit_robustness, add_benign_auth_typos, reduce_attack_volume,
    scale_latency_and_bytes, verify_splits,
)
from scripts.model_features import WINDOW_MODEL_INPUT_COLUMNS
from scripts.train_detector import train_and_evaluate
from test_step5_ml import make_rows


def features():
    return {
        **{name: 0.0 for name in WINDOW_MODEL_INPUT_COLUMNS},
        "request_count": 10.0,
        "request_rate_per_second": 10 / 60,
        "get_ratio": 1.0,
        "post_ratio": 0.0,
        "unique_path_count": 2.0,
        "mean_duration_ms": 20.0,
        "mean_request_bytes": 100.0,
        "mean_response_bytes": 200.0,
    }


class Step6CounterfactualTests(unittest.TestCase):
    def test_split_manifest_rejects_overlapping_ids(self):
        records = [{"run_id": "a", "label": "simulated_benign"},
                   {"run_id": "b", "label": "simulated_brute_force"},
                   {"run_id": "c", "label": "simulated_benign"}]
        with self.assertRaisesRegex(ValueError, "Run leakage"):
            verify_splits(records, {"train": ["a"], "validation": ["a", "b"], "test": ["c"]})

    def test_split_manifest_rejects_missing_runs(self):
        records = [{"run_id": "a", "label": "simulated_benign"},
                   {"run_id": "b", "label": "simulated_brute_force"},
                   {"run_id": "c", "label": "simulated_benign"},
                   {"run_id": "d", "label": "simulated_brute_force"}]
        with self.assertRaisesRegex(ValueError, "mismatch"):
            verify_splits(records, {"train": ["a"], "validation": ["b"], "test": ["c"]})

    def test_split_manifest_rejects_duplicate_ids(self):
        with self.assertRaisesRegex(ValueError, "Duplicate run ID"):
            verify_splits([], {"train": ["a", "a"], "validation": ["b"], "test": ["c"]})

    def test_noisy_benign_injects_two_auth_typos_consistently(self):
        f = features()
        original = copy.deepcopy(f)
        result = add_benign_auth_typos(f, 60)
        self.assertEqual(f, original)
        self.assertEqual(result["request_count"], 12)
        self.assertAlmostEqual(result["request_rate_per_second"], 0.2)
        self.assertAlmostEqual(result["get_ratio"] + result["post_ratio"], 1.0)
        self.assertEqual(result["failed_login_count"], 2)
        self.assertEqual(result["login_attempt_count"], 2)
        self.assertAlmostEqual(result["http_401_ratio"], 2 / 12)
        self.assertAlmostEqual(result["http_4xx_ratio"], 2 / 12)

    def test_invalid_seconds_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "window_seconds"):
            add_benign_auth_typos(features(), 0)
        with self.assertRaisesRegex(ValueError, "window_seconds"):
            reduce_attack_volume(features(), float('nan'))

    def test_latency_payload_shift_does_not_mutate_inputs(self):
        f = features()
        before = dict(f)
        changed = scale_latency_and_bytes(f)
        self.assertEqual(f, before)
        self.assertEqual(changed["mean_duration_ms"], 31.0)
        self.assertEqual(changed["mean_request_bytes"], 125.0)
        self.assertEqual(changed["mean_response_bytes"], 160.0)

    def test_lower_volume_keeps_counts_bounded(self):
        f = features()
        f.update({"request_count": 13, "request_rate_per_second": 13 / 60,
                  "login_attempt_count": 5, "failed_login_count": 5,
                  "unique_path_count": 9})
        changed = reduce_attack_volume(f, 60)
        self.assertEqual(f["request_count"], 13)
        self.assertEqual(changed["request_count"], 6)
        self.assertLessEqual(changed["failed_login_count"], changed["login_attempt_count"])
        self.assertLessEqual(changed["unique_path_count"], changed["request_count"])
        self.assertAlmostEqual(changed["request_rate_per_second"], 0.1)


class Step6EndToEndAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.dataset = cls.root / 'window_features.csv'
        rows = make_rows(n=20)
        for row in rows:
            row['window_seconds'] = 60
        with cls.dataset.open('w', encoding='utf-8', newline='') as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        cls.ml_results = cls.root / 'ml_results'
        train_and_evaluate(cls.dataset, cls.ml_results, seed=42, trees=50)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_reproduces_frozen_test_metrics_and_writes_report(self):
        output = self.root / 'audit.json'
        report = audit_robustness(self.dataset, self.ml_results, output)
        self.assertTrue(output.exists())
        self.assertTrue(report['split_integrity']['saved_holdout_metrics_reproduced'])
        self.assertTrue(report['split_integrity']['threshold_reproduced_from_benign_validation'])
        self.assertEqual(report['split_integrity']['overlap_count'], 0)
        self.assertEqual(report['reference_original_test']['n_windows'], 16)
        self.assertEqual(set(report['what_if_cases']), {
            'latency_payload_shift_all_test', 'two_auth_typos_benign_only',
            'reduced_attack_volume_attack_only'})
        self.assertEqual(report['what_if_cases']['two_auth_typos_benign_only']['n_windows'], 4)

    def test_audit_is_deterministic_and_never_modifies_model(self):
        artifact = self.ml_results / 'isolation_forest.joblib'
        before = artifact.read_bytes()
        one = audit_robustness(self.dataset, self.ml_results, self.root / 'audit-1.json')
        two = audit_robustness(self.dataset, self.ml_results, self.root / 'audit-2.json')
        one.pop('source_model_dir'); two.pop('source_model_dir')
        self.assertEqual(one, two)
        self.assertEqual(before, artifact.read_bytes())

    def test_tampered_threshold_is_rejected_without_output(self):
        metrics = self.ml_results / 'metrics.json'
        original = metrics.read_text(encoding='utf-8')
        corrupted = json.loads(original)
        corrupted['threshold_from_benign_validation_only'] += 0.1
        try:
            metrics.write_text(json.dumps(corrupted), encoding='utf-8')
            output = self.root / 'audit-invalid.json'
            with self.assertRaisesRegex(ValueError, 'threshold'):
                audit_robustness(self.dataset, self.ml_results, output)
            self.assertFalse(output.exists())
        finally:
            metrics.write_text(original, encoding='utf-8')


if __name__ == '__main__':
    unittest.main()
