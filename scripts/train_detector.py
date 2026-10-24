"""Isolation Forest + fixed-rule baseline, with run-separated holdout evaluation.

Use ONLY controlled lab data for this prototype. No model is reported as a
production security detector. Test data are never used to fit or tune thresholds.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

from scripts.model_features import WINDOW_MODEL_INPUT_COLUMNS, select_window_model_features

LABEL_BENIGN = "simulated_benign"
ATTACK_LABELS = frozenset({"simulated_brute_force", "simulated_path_scan", "simulated_mixed_attack"})
VALID_LABELS = ATTACK_LABELS | {LABEL_BENIGN}


def read_windows(path: Path) -> list[dict[str, object]]:
    required = set(WINDOW_MODEL_INPUT_COLUMNS) | {"simulation_run_id", "scenario_label", "label_source", "source_ip", "window_start"}
    records = []
    seen = set()
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Missing dataset columns: {sorted(missing)}")
        for index, row in enumerate(reader, 2):
            run_id = row["simulation_run_id"].strip()
            label = row["scenario_label"].strip()
            if not run_id or label not in VALID_LABELS or row["label_source"] != "controlled_simulation":
                raise ValueError(f"Row {index}: missing run, invalid label or untrusted label source")
            key = (run_id, row["source_ip"], row["window_start"])
            if key in seen:
                raise ValueError(f"Row {index}: duplicate window key {key}")
            seen.add(key)
            try:
                features = select_window_model_features(row)
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError(f"Row {index}: invalid numeric features: {exc}") from exc
            if any(not math.isfinite(x) or x < 0 for x in features.values()):
                raise ValueError(f"Row {index}: model features must be finite and nonnegative")
            records.append({"run_id":run_id, "label":label, "features":features})
    if not records:
        raise ValueError("Input feature dataset is empty")
    return records


def stratified_run_split(records: list[dict[str, object]], seed: int = 42) -> dict[str, list[dict[str, object]]]:
    """Split independent simulation run IDs, preserving every attack type."""
    import random
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for item in records:
        grouped[str(item["run_id"])].append(item)
    classes: dict[str, list[str]] = defaultdict(list)
    for run, rows in grouped.items():
        labels = {str(row["label"]) for row in rows}
        if LABEL_BENIGN in labels and len(labels) > 1:
            raise ValueError(f"Run {run} mixes benign and attack labels")
        # One mixed replay can span two time buckets; treat the whole run
        # as an attack group for splitting, while keeping per-window labels.
        group_label = next(iter(labels)) if len(labels) == 1 else "simulated_mixed_attack"
        classes[group_label].append(run)
    if LABEL_BENIGN not in classes or not any(k in classes for k in ATTACK_LABELS):
        raise ValueError("Need both benign and attack simulation runs")
    rng = random.Random(seed)
    parts = {"train":[], "validation":[], "test":[]}
    for label, runs in sorted(classes.items()):
        if len(runs) < 15:
            raise ValueError(f"Not enough independent runs of {label}: {len(runs)}; need >=15")
        runs = sorted(runs)
        rng.shuffle(runs)
        n_test = max(3, round(len(runs)*0.2))
        n_val = max(3, round(len(runs)*0.2))
        buckets = {
            "test": runs[:n_test],
            "validation": runs[n_test:n_test+n_val],
            "train": runs[n_test+n_val:],
        }
        for part, ids in buckets.items():
            for run in ids:
                parts[part].extend(grouped[run])
    sets = {p:{str(z["run_id"]) for z in rows} for p,rows in parts.items()}
    if any(sets[a] & sets[b] for a,b in (("train","validation"),("train","test"),("validation","test"))):
        raise RuntimeError("Run leakage detected across data splits")
    return parts


def feature_matrix(rows: list[dict[str, object]]):
    import numpy as np
    return np.asarray([[float(item["features"][col]) for col in WINDOW_MODEL_INPUT_COLUMNS] for item in rows], dtype=float)


def labels_binary(rows: list[dict[str, object]]):
    import numpy as np
    return np.asarray([int(row["label"] != LABEL_BENIGN) for row in rows], dtype=int)


def rule_baseline(features: dict[str, float]) -> int:
    """Predefined heuristic, deliberately not tuned using held-out data."""
    return int(
        features["failed_login_count"] >= 3 or
        features["unique_path_count"] >= 6 or
        (features["request_count"] >= 8 and features["http_4xx_ratio"] >= 0.8)
    )


def compute_metrics(y_true, y_pred, scores=None) -> dict[str, object]:
    from sklearn.metrics import (average_precision_score, confusion_matrix,
                                 f1_score, precision_score, recall_score)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]
    metrics = {
        "true_negative": tn, "false_positive": fp, "false_negative": fn, "true_positive": tp,
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "false_positive_rate": round(fp/(fp+tn),4) if (fp+tn)>0 else None,
    }
    if scores is not None and len(set(int(x) for x in y_true)) == 2:
        metrics["average_precision"] = round(float(average_precision_score(y_true, scores)),4)
    return metrics


def train_and_evaluate(input_file: Path, output_dir: Path, *, seed: int = 42, target_fpr: float = 0.05, trees: int = 200) -> dict[str, object]:
    import joblib
    import numpy as np
    import sklearn
    from sklearn.ensemble import IsolationForest

    if not 0.01 <= target_fpr <= 0.25:
        raise ValueError("target_fpr must be between 0.01 and 0.25")
    if not 50 <= trees <= 1000:
        raise ValueError("trees must be between 50 and 1000")
    records = read_windows(input_file)
    splits = stratified_run_split(records, seed)
    benign_train = [r for r in splits["train"] if r["label"] == LABEL_BENIGN]
    benign_validation = [r for r in splits["validation"] if r["label"] == LABEL_BENIGN]
    if len(benign_train) < 8 or len(benign_validation) < 3:
        raise ValueError("Insufficient independent benign windows in train or validation")

    model = IsolationForest(n_estimators=trees, contamination="auto", random_state=seed,
                            max_samples="auto", n_jobs=1)
    model.fit(feature_matrix(benign_train))
    # Higher scores mean *more* anomalous. Calibrate on BENIGN VALIDATION ONLY.
    val_normal_scores = -model.score_samples(feature_matrix(benign_validation))
    threshold = float(np.quantile(val_normal_scores, 1.0-target_fpr))

    results = {}
    predictions = []
    for partition in ("validation", "test"):
        rows = splits[partition]
        x = feature_matrix(rows)
        y = labels_binary(rows)
        scores = -model.score_samples(x)
        pred = (scores > threshold).astype(int)
        rule = np.asarray([rule_baseline(r["features"]) for r in rows], dtype=int)
        result = {
            "n_windows": len(rows),
            "n_unique_runs": len({r["run_id"] for r in rows}),
            "class_counts": dict(Counter(str(r["label"]) for r in rows)),
            "isolation_forest": compute_metrics(y, pred, scores),
            "fixed_rule_baseline": compute_metrics(y, rule),
            "attack_recall_by_scenario": {},
        }
        for cls in sorted(ATTACK_LABELS):
            idx = [i for i, row in enumerate(rows) if row["label"]==cls]
            if idx:
                result["attack_recall_by_scenario"][cls] = round(sum(int(pred[i]) for i in idx)/len(idx),4)
        results[partition] = result
        for i,row in enumerate(rows):
            predictions.append({
                "partition":partition, "simulation_run_id":row["run_id"],
                "true_label":row["label"],"anomaly_score":round(float(scores[i]),7),
                "isolation_forest_pred":int(pred[i]),"rule_baseline_pred":int(rule[i]),
            })

    result = {
        "status": "research-prototype-not-production",
        "dataset": str(input_file),
        "seed": seed, "target_benign_validation_fpr":target_fpr,
        "threshold_from_benign_validation_only": threshold,
        "features": list(WINDOW_MODEL_INPUT_COLUMNS),
        "training_benign_windows":len(benign_train),
        "splits":results,
        "limitations":[
            "Synthetic local lab traffic; cannot claim real-world detection performance",
            "Patterns are easy to distinguish; benign traffic lacks normal authentication errors",
            "Per-run window aggregation is for evaluation; deployment must not depend on run IDs",
            "Tiny validation counts make threshold calibration noisy",
            "Repeated templates across runs may overestimate generalization",
        ],
        "versions":{"scikit_learn":sklearn.__version__},
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir/"metrics.json").write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    (output_dir/"split_manifest.json").write_text(json.dumps({
        split:sorted({str(z["run_id"]) for z in rows}) for split,rows in splits.items()
    },indent=2)+"\n",encoding="utf-8")
    with (output_dir/"predictions.csv").open("w",encoding="utf-8",newline="") as handle:
        writer=csv.DictWriter(handle,fieldnames=list(predictions[0]))
        writer.writeheader();writer.writerows(predictions)
    joblib.dump({"model":model,"features":list(WINDOW_MODEL_INPUT_COLUMNS),"threshold":threshold},output_dir/"isolation_forest.joblib")
    return result


def main() -> int:
    parser=argparse.ArgumentParser(description="Run-aware train/validation/test evaluation of an Isolation Forest lab baseline")
    parser.add_argument("--input",type=Path,required=True)
    parser.add_argument("--output-dir",type=Path,required=True)
    parser.add_argument("--seed",type=int,default=42)
    parser.add_argument("--target-fpr",type=float,default=0.05)
    parser.add_argument("--trees",type=int,default=200)
    args=parser.parse_args()
    try:
        report=train_and_evaluate(args.input,args.output_dir,seed=args.seed,target_fpr=args.target_fpr,trees=args.trees)
    except (OSError,ValueError) as exc:
        parser.exit(2, f"Training failed: {exc}\n")
    print(json.dumps({
        "training_benign_windows":report["training_benign_windows"],
        "validation":report["splits"]["validation"],
        "test":report["splits"]["test"],
        "output_dir":str(args.output_dir),
        "important":"Scores apply only to controlled simulated traffic",
    },indent=2))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
