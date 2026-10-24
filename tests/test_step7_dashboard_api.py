"""FastAPI contract tests: read-only, bounded, no path traversal or joblib loads."""
from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from dashboard_api.main import create_app
from dashboard_api.store import ArtifactError, ArtifactStore
from scripts.model_features import WINDOW_MODEL_INPUT_COLUMNS

RUN = "step5_20261024T062626Z_demo77"


class DashboardAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.folder = self.root / RUN
        (self.folder / "ml_results").mkdir(parents=True)
        self.features = {key: 0.0 for key in WINDOW_MODEL_INPUT_COLUMNS}
        self.features.update({"request_count": 10, "request_rate_per_second": 10 / 60,
                              "get_ratio": 1.0, "unique_path_count": 2})
        self.summary = {
            "purpose": "controlled-local-simulation-only", "seed": 42,
            "runs_per_class": 40, "runs": {"benign": 40}, "simulation_requests": 10,
            "label_join": {"matched_labeled_events": 10, "unlabeled_events": 2,
                           "manifest_records_without_event": 0},
            "feature_engineering": {"windows": 1, "window_seconds": 60,
                                    "window_label_counts": {"simulated_benign": 1},
                                    "model_feature_columns": list(WINDOW_MODEL_INPUT_COLUMNS)},
            "output_dir": "/private/local/user/directory",
        }
        (self.folder / "data_summary.json").write_text(json.dumps(self.summary))
        self.window_file = self.folder / "window_features.csv"
        self._write_csv(self.window_file, [{
            "window_start":"2026-10-24T06:00:00+00:00", "window_end":"2026-10-24T06:01:00+00:00",
            "window_seconds":60,"service":"webapp", "source_ip":"198.51.100.7",
            "simulation_run_id":"run-demo", "scenario_label":"simulated_benign",
            "label_source":"controlled_simulation", **self.features,
        }])
        (self.folder / "ml_results/metrics.json").write_text(json.dumps({
            "status":"research-prototype-not-production", "seed":42,
            "splits":{"test":{"n_windows":1}},
            "dataset":"/private/local/user/directory", "training_benign_windows":20,
        }))
        self.pred_file = self.folder / "ml_results/predictions.csv"
        self._write_csv(self.pred_file, [{
            "partition":"test", "simulation_run_id":"run-demo", "true_label":"simulated_benign",
            "anomaly_score":0.45,"isolation_forest_pred":0,"rule_baseline_pred":0,
        }])
        (self.folder / "ml_results/robustness_report.json").write_text(json.dumps({
            "status":"offline-what-if-analysis-not-external-validation",
            "split_integrity":{"overlap_count":0},"what_if_cases":{},
            "source_dataset":"/private/local/user/directory",
        }))
        self.client = TestClient(create_app(self.root))

    def _write_csv(self, path, rows):
        with path.open("w",encoding="utf-8",newline="") as h:
            w=csv.DictWriter(h,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)

    def test_health_and_api_is_read_only(self):
        resp=self.client.get("/api/health")
        self.assertEqual(resp.status_code,200)
        self.assertTrue(resp.json()["read_only"])
        self.assertEqual(self.client.post("/api/runs" ).status_code,405)

    def test_run_discovery_and_summary_do_not_leak_local_paths(self):
        discovered=self.client.get("/api/runs")
        self.assertEqual(discovered.status_code,200)
        self.assertEqual(discovered.json()["runs"][0]["run_id"],RUN)
        result=self.client.get(f"/api/runs/{RUN}/summary")
        self.assertEqual(result.status_code,200)
        self.assertEqual(result.json()["matched_labeled_events"],10)
        self.assertNotIn("output_dir",result.json())
        self.assertNotIn("/private/local",json.dumps(result.json()))

    def test_windows_returns_numeric_features_and_metadata_separately(self):
        resp=self.client.get(f"/api/runs/{RUN}/windows")
        self.assertEqual(resp.status_code,200)
        row=resp.json()["rows"][0]
        self.assertEqual(row["request_count"],10)
        self.assertEqual(set(WINDOW_MODEL_INPUT_COLUMNS)&set(row),set(WINDOW_MODEL_INPUT_COLUMNS))
        self.assertEqual(row["scenario_label"],"simulated_benign")

    def test_invalid_scenario_and_limit_are_rejected(self):
        url=f"/api/runs/{RUN}/windows"
        self.assertEqual(self.client.get(url,params={"scenario":"made-up"}).status_code,422)
        self.assertEqual(self.client.get(url,params={"limit":2000}).status_code,422)
        self.assertEqual(self.client.get(url,params={"limit":0}).status_code,422)

    def test_run_id_traversal_and_missing_are_rejected(self):
        self.assertEqual(self.client.get("/api/runs/not-a-run/summary").status_code,422)
        self.assertEqual(self.client.get("/api/runs/step5_00000000_missing/summary").status_code,404)
        self.assertNotEqual(self.client.get("/api/runs/%2E%2E%2Fetc/summary").status_code,200)

    def test_metrics_are_whitelisted_and_model_is_never_loaded(self):
        # Joblib file intentionally contains junk; reading metrics MUST still work.
        (self.folder / "ml_results/isolation_forest.joblib").write_bytes(b"not-a-model")
        resp=self.client.get(f"/api/runs/{RUN}/metrics")
        self.assertEqual(resp.status_code,200)
        self.assertNotIn("dataset",resp.json())
        self.assertEqual(resp.json()["status"],"research-prototype-not-production")

    def test_predictions_and_robustness_endpoints(self):
        pred=self.client.get(f"/api/runs/{RUN}/predictions", params={"partition":"test"})
        self.assertEqual(pred.status_code,200)
        self.assertEqual(pred.json()["rows"][0]["anomaly_score"],0.45)
        self.assertEqual(self.client.get(f"/api/runs/{RUN}/predictions",params={"partition":"train"}).status_code,422)
        report=self.client.get(f"/api/runs/{RUN}/robustness")
        self.assertEqual(report.status_code,200)
        self.assertNotIn("source_dataset",report.json())

    def test_invalid_numeric_window_is_rejected(self):
        with self.window_file.open("r", encoding="utf-8", newline="") as h:
            rows=list(csv.DictReader(h))
        rows[0]["request_count"]="NaN"
        self._write_csv(self.window_file, rows)
        self.assertEqual(self.client.get(f"/api/runs/{RUN}/windows").status_code,422)

    def test_symlink_artifact_is_rejected_if_outside_run(self):
        (self.folder / "data_summary.json").unlink()
        external=self.root / "outside.json"
        external.write_text("{\"private\": true}")
        (self.folder / "data_summary.json").symlink_to(external)
        resp=self.client.get(f"/api/runs/{RUN}/summary")
        self.assertEqual(resp.status_code,422)

    def test_missing_root_and_model_artifacts_do_not_crash(self):
        c=TestClient(create_app(self.root / "missing-folder"))
        self.assertEqual(c.get("/api/runs").json(), {"runs":[]})
        (self.folder / "ml_results/metrics.json").unlink()
        self.assertEqual(self.client.get(f"/api/runs/{RUN}/metrics").status_code,404)

    def test_artifact_size_is_bounded(self):
        with self.window_file.open("wb") as fh:
            fh.seek(16*1024*1024)
            fh.write(b"!")
        self.assertEqual(self.client.get(f"/api/runs/{RUN}/windows").status_code,422)


if __name__ == '__main__':
    unittest.main()
