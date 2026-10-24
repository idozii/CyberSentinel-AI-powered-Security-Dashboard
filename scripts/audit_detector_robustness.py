"""Audit a *trusted local* Step 5 model, then evaluate frozen-model counterfactual stress cases.

The counterfactuals are feature-space thought experiments, NOT independently
collected attacks or production-detection validation. Never tune using this report.
Only load joblib artifacts created by you in this repository; pickle is unsafe.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from scripts.model_features import WINDOW_MODEL_INPUT_COLUMNS
from scripts.train_detector import (ATTACK_LABELS, LABEL_BENIGN, compute_metrics,
                                    feature_matrix, labels_binary, read_windows,
                                    rule_baseline)

PARTITIONS = ("train", "validation", "test")


def verify_splits(records: list[dict[str, object]], manifest: dict[str, Any]) -> dict[str, list[dict[str, object]]]:
    """Fail closed on partition overlap, omissions, fabricated IDs or empty partitions."""
    if not isinstance(manifest, dict) or set(manifest) != set(PARTITIONS):
        raise ValueError("Split manifest must have exactly train, validation and test")
    groups = {}
    for name in PARTITIONS:
        ids = manifest[name]
        if not isinstance(ids, list) or not ids or any(not isinstance(x, str) or not x for x in ids):
            raise ValueError(f"Invalid or empty {name} split")
        if len(ids) != len(set(ids)):
            raise ValueError(f"Duplicate run ID in {name} split")
        groups[name] = set(ids)
    if any(groups[x] & groups[y] for x, y in (("train", "validation"), ("train", "test"), ("validation", "test"))):
        raise ValueError("Run leakage: run ID appears in multiple splits")
    expected = {str(row["run_id"]) for row in records}
    union = set().union(*groups.values())
    if expected != union:
        raise ValueError(f"Split manifest run mismatch: missing={len(expected-union)}, extra={len(union-expected)}")
    split_rows = {name: [r for r in records if r["run_id"] in groups[name]] for name in PARTITIONS}
    for name in ("validation", "test"):
        labels = {str(row["label"]) for row in split_rows[name]}
        if LABEL_BENIGN not in labels or not (labels & ATTACK_LABELS):
            raise ValueError(f"{name} lacks benign or attack examples")
    return split_rows


def add_benign_auth_typos(features: dict[str, float], window_seconds: float, n_failures: int = 2) -> dict[str, float]:
    """Hypothetical benign user mistyping a password twice in the same window."""
    if not (math.isfinite(window_seconds) and window_seconds > 0):
        raise ValueError("window_seconds must be positive and finite")
    if n_failures not in (1, 2):
        raise ValueError("Only one or two benign typos are modeled")
    f = dict(features)
    old = f["request_count"]
    if old <= 0:
        raise ValueError("Cannot perturb an empty window")
    new = old + n_failures
    f["request_count"] = new
    f["request_rate_per_second"] = new / window_seconds
    f["get_ratio"] = f["get_ratio"] * old / new
    f["post_ratio"] = (f["post_ratio"] * old + n_failures) / new
    f["login_attempt_count"] += n_failures
    f["failed_login_count"] += n_failures
    f["unique_path_count"] = min(new, f["unique_path_count"] + 1)
    f["http_401_ratio"] = (f["http_401_ratio"] * old + n_failures) / new
    f["http_4xx_ratio"] = (f["http_4xx_ratio"] * old + n_failures) / new
    f["http_404_ratio"] = f["http_404_ratio"] * old / new
    f["query_ratio"] = f["query_ratio"] * old / new
    # Assume these hypothetical requests have representative sizes/timing.
    # No claim is made that these values match authentic traffic.
    return f


def scale_latency_and_bytes(features: dict[str, float]) -> dict[str, float]:
    """Controlled feature-space distribution shift, not real measured traffic."""
    f = dict(features)
    f["mean_duration_ms"] = f["mean_duration_ms"] * 1.5 + 1.0
    f["mean_request_bytes"] *= 1.25
    f["mean_response_bytes"] *= 0.8
    return f


def reduce_attack_volume(features: dict[str, float], window_seconds: float) -> dict[str, float]:
    """Counterfactual proportional thinning; not a packet-level replay."""
    if not (math.isfinite(window_seconds) and window_seconds > 0):
        raise ValueError("window_seconds must be positive and finite")
    f = dict(features)
    old = f["request_count"]
    if old <= 0:
        raise ValueError("Cannot perturb an empty window")
    new = max(1.0, math.floor(old * 0.5))
    factor = new / old
    f["request_count"] = new
    f["request_rate_per_second"] = new / window_seconds
    f["login_attempt_count"] = min(new, round(f["login_attempt_count"] * factor))
    f["failed_login_count"] = min(f["login_attempt_count"], round(f["failed_login_count"] * factor))
    f["unique_path_count"] = min(new, max(1, round(f["unique_path_count"] * factor)))
    # Ratios approximate proportional sampling, not independently observed events.
    return f


def metric_summary(rows: list[dict[str, object]], model: Any, threshold: float) -> dict[str, Any]:
    x = feature_matrix(rows)
    y = labels_binary(rows)
    scores = -model.score_samples(x)
    pred = (scores > threshold).astype(int)
    rules = np.asarray([rule_baseline(r["features"]) for r in rows], dtype=int)
    by_class: dict[str, dict[str, object]] = {}
    for label in sorted(ATTACK_LABELS):
        indices = [i for i, r in enumerate(rows) if r["label"] == label]
        if indices:
            by_class[label] = {"total": len(indices), "detected": int(pred[indices].sum()),
                               "recall": round(float(pred[indices].mean()), 4)}
    return {"n_windows": len(rows), "class_counts": dict(Counter(str(r["label"]) for r in rows)),
            "isolation_forest": compute_metrics(y, pred, scores),
            "fixed_rule_baseline": compute_metrics(y, rules),
            "attack_recall_by_scenario": by_class}


def assert_original_test_matches(report: dict[str, Any], saved: dict[str, Any]) -> None:
    test = saved.get("splits", {}).get("test", {})
    for key in ("isolation_forest", "fixed_rule_baseline"):
        if report[key] != test.get(key):
            raise ValueError(f"Saved test metrics do not match frozen model: {key}")
    if report["n_windows"] != test.get("n_windows") or report["class_counts"] != test.get("class_counts"):
        raise ValueError("Saved test counts do not match dataset and split manifest")


def audit_robustness(dataset: Path, ml_results: Path, output: Path) -> dict[str, Any]:
    """Never refit model or calibrate thresholds; verify Step 5 then stress frozen model."""
    metrics = json.loads((ml_results / "metrics.json").read_text(encoding="utf-8"))
    manifest = json.loads((ml_results / "split_manifest.json").read_text(encoding="utf-8"))
    records = read_windows(dataset)
    split_rows = verify_splits(records, manifest)

    # IMPORTANT: load only artifacts produced by the user themselves (joblib uses pickle).
    bundle = joblib.load(ml_results / "isolation_forest.joblib")
    if not isinstance(bundle, dict) or list(bundle.get("features", [])) != list(WINDOW_MODEL_INPUT_COLUMNS):
        raise ValueError("Trained model feature contract mismatch")
    model = bundle.get("model")
    if not hasattr(model, "score_samples") or not hasattr(model, "n_features_in_") or model.n_features_in_ != len(WINDOW_MODEL_INPUT_COLUMNS):
        raise ValueError("Invalid or incompatible trained estimator")
    threshold = float(bundle["threshold"])
    if not math.isfinite(threshold) or not math.isclose(threshold, float(metrics["threshold_from_benign_validation_only"]), abs_tol=1e-9):
        raise ValueError("Saved model and reported threshold disagree")
    benign_train = [r for r in split_rows["train"] if r["label"] == LABEL_BENIGN]
    benign_validation = [r for r in split_rows["validation"] if r["label"] == LABEL_BENIGN]
    if len(benign_train) != metrics.get("training_benign_windows") or len(benign_validation) < 3:
        raise ValueError("Benign train/validation count mismatch")
    target_fpr = float(metrics["target_benign_validation_fpr"])
    calibrated = float(np.quantile(-model.score_samples(feature_matrix(benign_validation)), 1.0-target_fpr))
    if not math.isclose(calibrated, threshold, abs_tol=1e-8):
        raise ValueError("Threshold is not reproducible from benign validation only")

    original = metric_summary(split_rows["test"], model, threshold)
    assert_original_test_matches(original, metrics)
    # Pair read_windows' records with raw CSV metadata in the same source order.
    with dataset.open("r", encoding="utf-8", newline="") as h:
        csv_rows = list(csv.DictReader(h))
    if len(csv_rows) != len(records) or "window_seconds" not in (csv_rows[0] if csv_rows else {}):
        raise ValueError("Dataset missing window_seconds or inconsistent row count")
    seconds = {}
    for row, record in zip(csv_rows, records):
        duration = float(row["window_seconds"])
        if not math.isfinite(duration) or duration <= 0:
            raise ValueError("Invalid window_seconds")
        seconds[id(record)] = duration
    test_ids = {id(x) for x in split_rows["test"]}
    # Index by object identity to retain exactly the source rows in test.
    shifted, noisy_benign, low_volume = [], [], []
    for record in records:
        if id(record) not in test_ids:
            continue
        f = dict(record["features"])
        shifted.append({**record, "features": scale_latency_and_bytes(f)})
        if record["label"] == LABEL_BENIGN:
            noisy_benign.append({**record, "features": add_benign_auth_typos(f, seconds[id(record)])})
        else:
            low_volume.append({**record, "features": reduce_attack_volume(f, seconds[id(record)])})
    if not noisy_benign or not low_volume:
        raise ValueError("Need both benign and attack test cases")

    shift_metrics = metric_summary(shifted, model, threshold)
    noisy_metrics = metric_summary(noisy_benign, model, threshold)
    volume_metrics = metric_summary(low_volume, model, threshold)
    output_data = {
        "status": "offline-what-if-analysis-not-external-validation",
        "source_dataset": str(dataset), "source_model_dir": str(ml_results),
        "frozen_threshold": threshold,
        "split_integrity": {"train_runs": len(manifest["train"]),
                            "validation_runs": len(manifest["validation"]),
                            "test_runs": len(manifest["test"]), "overlap_count": 0,
                            "threshold_reproduced_from_benign_validation": True,
                            "saved_holdout_metrics_reproduced": True},
        "reference_original_test": original,
        "what_if_cases": {
            "latency_payload_shift_all_test": shift_metrics,
            "two_auth_typos_benign_only": noisy_metrics,
            "reduced_attack_volume_attack_only": volume_metrics,
        },
        "limitations": [
            "Feature-space counterfactuals are hypothetical; not replayed or independently collected HTTP events.",
            "Derived from existing held-out runs; do not use as a new independent test set.",
            "Do not tune thresholds, features, model parameters or select the best model based on this report.",
            "Simulated templates and run-ID windows do not establish production deployment performance.",
            "Only load trusted local joblib artifacts; deserialization may execute code.",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = output.with_name(output.name + f".staging.{os.getpid()}.{uuid.uuid4().hex}")
    try:
        staging.write_text(json.dumps(output_data, indent=2) + "\n", encoding="utf-8")
        os.replace(staging, output)
    finally:
        staging.unlink(missing_ok=True)
    return output_data


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit trusted Step 5 holdout & frozen-model counterfactual robustness")
    parser.add_argument("--input", type=Path, required=True, help="Step 5 window_features.csv")
    parser.add_argument("--ml-results", type=Path, required=True, help="Directory with OWN Step 5 model artifacts")
    parser.add_argument("--output", type=Path, required=True, help="Output JSON outside version control")
    args = parser.parse_args()
    try:
        report = audit_robustness(args.input, args.ml_results, args.output)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, f"Robustness audit failed: {exc}\n")
    print(json.dumps({"status": report["status"], "split_integrity": report["split_integrity"],
                      "reference_original_test": report["reference_original_test"],
                      "what_if_cases": report["what_if_cases"], "output": str(args.output)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
