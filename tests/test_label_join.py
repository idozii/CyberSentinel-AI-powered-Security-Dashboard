"""Tests for trusted-label join and prevention of obvious simulation leakage."""
import csv
import json
import tempfile
import unittest
from pathlib import Path

from scripts.build_labeled_dataset import join_labels, load_manifest
from scripts.model_features import MODEL_INPUT_COLUMNS, EXCLUDED_FROM_MODEL, select_model_features


class LabelJoinTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.events = self.root / "events.csv"
        self.manifest = self.root / "manifest.jsonl"
        self.output = self.root / "labeled.csv"
        with self.events.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["request_id", *MODEL_INPUT_COLUMNS, "user_agent", "path"])
            w.writeheader()
            for idx in range(3):
                w.writerow({"request_id": f"req-{idx}", "http_method": "GET", "query_present": "False",
                            "status_code": "200", "request_bytes": "100", "response_bytes": "120",
                            "duration_ms": "20", "user_agent": "fake-scanner" if idx == 1 else "browser", "path": "/"})
        with self.manifest.open("w", encoding="utf-8") as f:
            f.write(json.dumps({"request_id": "req-0", "run_id": "r1", "scenario_label": "simulated_benign"})+"\n")
            f.write(json.dumps({"request_id": "req-1", "run_id": "r1", "scenario_label": "simulated_path_scan"})+"\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_join_uses_request_id_only_and_unknown_stays_unlabeled(self):
        summary = join_labels(self.events, self.manifest, self.output, strict=True)
        self.assertEqual(summary["matched_labeled_events"], 2)
        self.assertEqual(summary["unlabeled_events"], 1)
        with self.output.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual([r["scenario_label"] for r in rows],
                         ["simulated_benign", "simulated_path_scan", "unlabeled"])
        self.assertEqual(rows[2]["label_source"], "none")
        self.assertEqual(rows[1]["label_source"], "controlled_simulation")

    def test_duplicate_manifest_request_id_fails(self):
        with self.manifest.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"request_id": "req-0", "run_id": "r2", "scenario_label": "simulated_brute_force"})+"\n")
        with self.assertRaisesRegex(ValueError, "Duplicate request_id"):
            load_manifest(self.manifest)

    def test_strict_mode_rejects_missing_event_and_no_partial_output(self):
        with self.manifest.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"request_id": "not-in-events", "run_id": "r1", "scenario_label": "simulated_benign"})+"\n")
        with self.assertRaisesRegex(ValueError, "not found"):
            join_labels(self.events, self.manifest, self.output, strict=True)
        self.assertFalse(self.output.exists())

    def test_invalid_label_fails(self):
        self.manifest.write_text(json.dumps({"request_id": "req-0", "run_id": "r1", "scenario_label": "phishing"})+"\n")
        with self.assertRaisesRegex(ValueError, "unrecognized"):
            load_manifest(self.manifest)

    def test_model_feature_allowlist_excludes_leaky_identifiers(self):
        row = {col: "test" for col in MODEL_INPUT_COLUMNS}
        row.update({"scenario_label": "simulated_path_scan", "user_agent": "fake-scanner",
                    "path": "/.env", "source_ip": "198.51.100.77", "request_id": "req-1"})
        selected = select_model_features(row)
        self.assertEqual(set(selected), set(MODEL_INPUT_COLUMNS))
        self.assertFalse(set(selected) & EXCLUDED_FROM_MODEL)

    def test_duplicate_event_id_fails(self):
        with self.events.open("a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["request_id", *MODEL_INPUT_COLUMNS, "user_agent", "path"])
            w.writerow({"request_id": "req-0"})
        with self.assertRaisesRegex(ValueError, "Duplicate event request_id"):
            join_labels(self.events, self.manifest, self.output)


if __name__ == "__main__":
    unittest.main()
