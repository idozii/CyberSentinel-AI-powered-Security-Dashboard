"""Step 5: fail-closed tests for dataset split, leakage and baseline training."""
from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from scripts.model_features import WINDOW_MODEL_INPUT_COLUMNS
from scripts.train_detector import (read_windows, stratified_run_split, rule_baseline,
                                    train_and_evaluate)
from scripts.run_lab_experiments import generate_plan, check_proxy


def make_rows(n=20, windows_per_run=1):
    rows=[]
    classes=["simulated_benign", "simulated_brute_force", "simulated_path_scan", "simulated_mixed_attack"]
    for cls in classes:
        for run_index in range(n):
            for w in range(windows_per_run):
                benign = cls == "simulated_benign"
                vals={col:0.0 for col in WINDOW_MODEL_INPUT_COLUMNS}
                vals.update({
                    "request_count":float(5 + run_index % 12),
                    "request_rate_per_second":(5+run_index%12)/60.0,
                    "get_ratio": 1.0 if benign or cls=="simulated_path_scan" else 0.2,
                    "post_ratio": 0.0 if benign or cls=="simulated_path_scan" else 0.8,
                    "login_attempt_count":0.0 if benign or cls=="simulated_path_scan" else float(4 + run_index % 9),
                    "failed_login_count":0.0 if benign or cls=="simulated_path_scan" else float(4 + run_index % 9),
                    "unique_path_count":2.0 if benign or cls=="simulated_brute_force" else 8.0,
                    "http_401_ratio":0.0 if benign or cls=="simulated_path_scan" else 0.8,
                    "http_404_ratio":0.0 if benign or cls=="simulated_brute_force" else 0.8,
                    "http_4xx_ratio":0.0 if benign else 0.8,
                    "query_ratio":0.0,
                    "mean_duration_ms":20.0+(run_index%5),
                    "mean_request_bytes":100.0+run_index,
                    "mean_response_bytes":200.0+run_index,
                })
                rows.append({"simulation_run_id":f"{cls}-{run_index}","scenario_label":cls,
                             "label_source":"controlled_simulation", "source_ip":"198.51.100.5",
                             "window_start":f"2026-10-24T05:{w:02d}:00+00:00", **vals})
    return rows


class Step5Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dataset = self.root/"features.csv"

    def write(self, rows):
        with self.dataset.open("w",encoding="utf-8",newline="") as f:
            writer=csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

    def test_generation_plan_bounded_and_balanced(self):
        a=generate_plan(20,42)
        self.assertEqual(a,generate_plan(20,42))
        self.assertEqual(len(a),80)
        self.assertEqual({i["scenario"] for i in a},{"benign","brute-force","scan","mixed"})
        self.assertTrue(all(1 <= i["concurrency"] <= 4 for i in a))

    def test_generation_plan_refuses_invalid_size(self):
        with self.assertRaises(ValueError):
            generate_plan(2,42)

    def test_nonlocal_proxy_rejected_before_any_network_access(self):
        with self.assertRaises(ValueError):
            check_proxy("http://example.com")

    def test_no_run_leaks_and_all_scenarios_represented(self):
        self.write(make_rows(windows_per_run=2))
        records=read_windows(self.dataset)
        p=stratified_run_split(records,seed=99)
        runs={k:{x["run_id"] for x in v} for k,v in p.items()}
        self.assertFalse(runs["train"] & runs["validation"])
        self.assertFalse(runs["train"] & runs["test"])
        self.assertFalse(runs["validation"] & runs["test"])
        self.assertEqual(sum(len(x) for x in p.values()),160)

    def test_leaky_extra_columns_never_become_features(self):
        rows=make_rows()
        for r in rows:
            r["user_agent"]="LITERAL_ATTACK_LABEL_"+r["scenario_label"]
            r["request_id"]="id-"+r["simulation_run_id"]
        self.write(rows)
        records=read_windows(self.dataset)
        self.assertEqual(set(records[0]["features"]),set(WINDOW_MODEL_INPUT_COLUMNS))
        self.assertNotIn("scenario_label",records[0]["features"])

    def test_duplicate_windows_fail(self):
        rows=make_rows()
        self.write(rows + [rows[0]])
        with self.assertRaisesRegex(ValueError,"duplicate window"):
            read_windows(self.dataset)

    def test_two_windows_cannot_train(self):
        self.write(make_rows(n=1))
        with self.assertRaisesRegex(ValueError,"Not enough independent runs"):
            train_and_evaluate(self.dataset,self.root/"output")

    def test_mixed_run_spanning_minutes_stays_together(self):
        rows=make_rows(n=20)
        for item in rows:
            if item["simulation_run_id"]=="simulated_mixed_attack-0":
                new=dict(item);new["window_start"]="2026-10-24T05:45:00+00:00"
                new["scenario_label"]="simulated_path_scan"
                rows.append(new)
                break
        self.write(rows)
        partitions=stratified_run_split(read_windows(self.dataset))
        present=[k for k,v in partitions.items() if any(row["run_id"]=="simulated_mixed_attack-0" for row in v)]
        self.assertEqual(len(present),1)

    def test_baseline_fixed_rules(self):
        row={k:0 for k in WINDOW_MODEL_INPUT_COLUMNS}
        self.assertEqual(rule_baseline(row),0)
        row["failed_login_count"]=3
        self.assertEqual(rule_baseline(row),1)

    def test_train_saves_metrics_and_holdout_predictions(self):
        self.write(make_rows(n=20))
        output=self.root/"trained"
        report=train_and_evaluate(self.dataset,output,seed=23,trees=50)
        self.assertTrue((output/"metrics.json").exists())
        self.assertTrue((output/"predictions.csv").exists())
        self.assertTrue((output/"isolation_forest.joblib").exists())
        parts=json.loads((output/"split_manifest.json").read_text())
        self.assertFalse(set(parts["train"]) & set(parts["test"]))
        self.assertEqual(len(report["features"]),14)
        self.assertIn("average_precision",report["splits"]["test"]["isolation_forest"])


if __name__=="__main__":
    unittest.main()
