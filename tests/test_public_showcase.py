"""Standard-library tests for the public, aggregate-only portfolio fixture."""
from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from dashboard.public_data import DATA_FILE, load_public_metrics, validate_public_metrics


class PublicShowcaseTests(unittest.TestCase):
    def setUp(self):
        self.data = load_public_metrics()

    def test_public_dataset_is_static_summary(self):
        self.assertEqual(self.data["display_mode"], "static_research_summary")
        self.assertEqual(self.data["source"]["simulation_runs"], 160)
        self.assertEqual(self.data["source"]["simulated_requests"], 2678)
        self.assertEqual(self.data["source"]["manifest_gaps"], 0)
        self.assertEqual(len(self.data["model"]["feature_names"]), 14)

    def test_test_confusion_and_scenarios_are_consistent(self):
        test = self.data["test"]
        m = test["isolation_forest"]
        self.assertEqual((m["tn"], m["fp"], m["fn"], m["tp"]), (8, 0, 17, 7))
        self.assertEqual(sum(v["detected"] for v in test["attack_scenarios"].values()), 7)

    def test_all_scenarios_present(self):
        self.assertEqual(set(self.data["windows_by_scenario"]), {
            "simulated_benign", "simulated_brute_force", "simulated_path_scan", "simulated_mixed_attack"})
        self.assertEqual(sum(self.data["windows_by_scenario"].values()), 160)

    def test_inconsistent_counts_rejected(self):
        corrupted = copy.deepcopy(self.data)
        corrupted["source"]["matched_requests"] = 2000
        with self.assertRaisesRegex(ValueError, "manifest coverage"):
            validate_public_metrics(corrupted)

    def test_mismatched_scenario_detection_rejected(self):
        corrupted = copy.deepcopy(self.data)
        corrupted["test"]["attack_scenarios"]["Path scanning"]["detected"] = 2
        with self.assertRaisesRegex(ValueError, "detected counts"):
            validate_public_metrics(corrupted)

    def test_only_bundled_aggregate_metrics_are_loaded(self):
        text = DATA_FILE.read_text(encoding="utf-8")
        self.assertNotIn("/home/idozii", text)
        self.assertNotIn("198.51.100.", text)
        self.assertNotIn("X-Forwarded-For", text)
        self.assertNotIn("password", text.lower())
        self.assertNotIn("request_id", text)

    def test_missing_fixture_is_not_silently_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                load_public_metrics(Path(tmp) / "missing.json")


if __name__ == "__main__":
    unittest.main()
