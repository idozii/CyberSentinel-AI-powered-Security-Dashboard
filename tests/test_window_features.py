"""Step 4 tests: aggregation, trusted labels, isolation, leakage and validation."""
import csv
import tempfile
import unittest
from pathlib import Path

from scripts.build_window_features import build_windows
from scripts.model_features import WINDOW_MODEL_INPUT_COLUMNS, select_window_model_features


FIELDNAMES = [
    "captured_at", "service", "source_ip", "request_id", "simulation_run_id",
    "scenario_label", "label_source", "http_method", "path", "status_code",
    "request_bytes", "response_bytes", "duration_ms", "query_present",
    "user_agent",
]


def event(request_id, timestamp, label, run="run-1", ip="198.51.100.7", path="/", status="200", method="GET", source="controlled_simulation"):
    return {
        "captured_at": timestamp, "service": "webapp", "source_ip": ip,
        "request_id": request_id, "simulation_run_id": run,
        "scenario_label": label, "label_source": source,
        "http_method": method, "path": path, "status_code": status,
        "request_bytes": "120", "response_bytes": "240",
        "duration_ms": "20.0", "query_present": "False",
        "user_agent": "CyberSentinel-brute-force" if label == "simulated_brute_force" else "browser",
    }


class WindowFeaturesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / "labeled.csv"
        self.output = self.root / "window_features.csv"

    def write(self, rows):
        with self.input.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writeheader()
            writer.writerows(rows)

    def results(self):
        with self.output.open("r", encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))

    def test_counts_and_rates_for_bruteforce(self):
        self.write([
            event("a", "2026-03-24T05:00:01Z", "simulated_brute_force", path="/login", status="401", method="POST"),
            event("b", "2026-03-24T05:00:05Z", "simulated_brute_force", path="/login", status="401", method="POST"),
            event("c", "2026-03-24T05:00:08Z", "simulated_brute_force", path="/", status="200"),
        ])
        summary = build_windows(self.input, self.output)
        rows = self.results()
        self.assertEqual(summary["windows"], 1)
        self.assertEqual(rows[0]["request_count"], "3")
        self.assertEqual(rows[0]["failed_login_count"], "2")
        self.assertEqual(rows[0]["login_attempt_count"], "2")
        self.assertEqual(rows[0]["unique_path_count"], "2")
        self.assertAlmostEqual(float(rows[0]["http_401_ratio"]), 2/3, places=5)
        self.assertEqual(rows[0]["scenario_label"], "simulated_brute_force")

    def test_unlabeled_are_excluded_not_benign(self):
        self.write([
            event("a", "2026-03-24T05:00:01+00:00", "unlabeled", source="none"),
            event("b", "2026-03-24T05:00:02+00:00", "simulated_benign"),
        ])
        summary = build_windows(self.input, self.output)
        self.assertEqual(summary["skipped_unlabeled_events"], 1)
        self.assertEqual(self.results()[0]["request_count"], "1")

    def test_run_ids_keep_simulation_runs_separate(self):
        self.write([
            event("a", "2026-03-24T05:00:01+00:00", "simulated_benign", run="benign-run"),
            event("b", "2026-03-24T05:00:05+00:00", "simulated_brute_force", run="attack-run", path="/login", status="401", method="POST"),
        ])
        summary = build_windows(self.input, self.output)
        self.assertEqual(summary["windows"], 2)
        self.assertEqual({r["scenario_label"] for r in self.results()}, {"simulated_benign", "simulated_brute_force"})

    def test_mixed_labels_are_never_benign(self):
        self.write([
            event("a", "2026-03-24T05:00:01Z", "simulated_path_scan", path="/.env", status="404"),
            event("b", "2026-03-24T05:00:02Z", "simulated_brute_force", path="/login", status="401", method="POST"),
        ])
        build_windows(self.input, self.output)
        self.assertEqual(self.results()[0]["scenario_label"], "simulated_mixed_attack")

    def test_time_window_boundary(self):
        self.write([
            event("a", "2026-03-24T05:00:59Z", "simulated_benign"),
            event("b", "2026-03-24T05:01:00Z", "simulated_benign"),
        ])
        self.assertEqual(build_windows(self.input, self.output)["windows"], 2)

    def test_identifiers_and_user_agent_never_model_inputs(self):
        self.write([event("a", "2026-03-24T05:00:01Z", "simulated_benign")])
        build_windows(self.input, self.output)
        numeric = select_window_model_features(self.results()[0])
        self.assertEqual(set(numeric), set(WINDOW_MODEL_INPUT_COLUMNS))
        for unsafe in ["source_ip", "simulation_run_id", "scenario_label", "user_agent", "path", "request_id"]:
            self.assertNotIn(unsafe, numeric)

    def test_duplicate_request_id_rejected_without_output(self):
        self.write([
            event("dup", "2026-03-24T05:00:01Z", "simulated_benign"),
            event("dup", "2026-03-24T05:00:02Z", "simulated_benign"),
        ])
        with self.assertRaisesRegex(ValueError, "duplicate request_id"):
            build_windows(self.input, self.output)
        self.assertFalse(self.output.exists())

    def test_invalid_timestamps_rejected(self):
        self.write([event("a", "2026-03-24T05:00:01", "simulated_benign")])
        with self.assertRaisesRegex(ValueError, "timezone"):
            build_windows(self.input, self.output)

    def test_invalid_numeric_rejected(self):
        row = event("a", "2026-03-24T05:00:01Z", "simulated_benign")
        row["duration_ms"] = "NaN"
        self.write([row])
        with self.assertRaisesRegex(ValueError, "finite"):
            build_windows(self.input, self.output)

    def test_untrusted_label_rejected(self):
        self.write([event("a", "2026-03-24T05:00:01Z", "simulated_benign", source="unknown")])
        with self.assertRaisesRegex(ValueError, "trusted simulation"):
            build_windows(self.input, self.output)

    def test_empty_labeled_set_rejected(self):
        self.write([event("a", "2026-03-24T05:00:01Z", "unlabeled", source="none")])
        with self.assertRaisesRegex(ValueError, "No trusted labeled events"):
            build_windows(self.input, self.output)

    def test_window_seconds_validation(self):
        self.write([event("a", "2026-03-24T05:00:01Z", "simulated_benign")])
        with self.assertRaisesRegex(ValueError, "between 10 and 3600"):
            build_windows(self.input, self.output, window_seconds=0)


if __name__ == "__main__":
    unittest.main()
