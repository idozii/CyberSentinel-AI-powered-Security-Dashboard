"""Validate and load anonymized aggregate experiment results for a public showcase.

This module deliberately reads only a bundled summary JSON. It cannot access
local telemetry logs, request-level labels, a FastAPI server or joblib models.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

DATA_FILE = Path(__file__).with_name("public_metrics.json")
LABELS = {
    "simulated_benign",
    "simulated_brute_force",
    "simulated_path_scan",
    "simulated_mixed_attack",
}


def validate_public_metrics(data: dict[str, Any]) -> dict[str, Any]:
    """Fail closed if the published report is internally inconsistent."""
    if data.get("schema_version") != "public_showcase.v1":
        raise ValueError("Unsupported public metrics schema")
    if data.get("display_mode") != "static_research_summary":
        raise ValueError("Only offline static results may be published")
    s = data.get("source", {})
    if not isinstance(s, dict):
        raise ValueError("Source metadata is missing")
    for key in ("simulation_runs", "simulated_requests", "matched_requests", "manifest_gaps", "feature_windows"):
        if type(s.get(key)) is not int or s[key] < 0:
            raise ValueError(f"Invalid source count: {key}")
    if s["matched_requests"] != s["simulated_requests"] or s["manifest_gaps"]:
        raise ValueError("Inconsistent manifest coverage")
    counts = data.get("windows_by_scenario", {})
    if not isinstance(counts, dict) or set(counts) != LABELS:
        raise ValueError("Unexpected simulation classes")
    if any(type(value) is not int or value < 0 for value in counts.values()):
        raise ValueError("Invalid window count")
    if sum(counts.values()) != s["feature_windows"] or sum(counts.values()) != s["simulation_runs"]:
        raise ValueError("Window/run totals disagree")
    if len(data.get("model", {}).get("feature_names", [])) != s.get("features"):
        raise ValueError("Feature count mismatch")

    test = data.get("test", {})
    validation = data.get("validation", {})
    split = data.get("splits", {})
    if not isinstance(test, dict) or not isinstance(validation, dict) or not isinstance(split, dict):
        raise ValueError("Missing experiment partitions")
    if split.get("test_windows") != split.get("test_benign", -1) + split.get("test_attack", -1):
        raise ValueError("Holdout partition count mismatch")
    for partition_name, partition in (("test", test), ("validation", validation)):
        metrics = partition.get("isolation_forest", {})
        n = sum(metrics.get(k, -1) for k in ("tn", "fp", "fn", "tp"))
        expected = split["test_windows"] if partition_name == "test" else split["validation_windows"]
        if n != expected:
            raise ValueError(f"Confusion counts mismatch for {partition_name}")
        for metric in ("precision", "recall", "f1", "fpr", "ap"):
            value = metrics.get(metric)
            if not isinstance(value, (float, int)) or not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError(f"Invalid {partition_name} metric {metric}")
    rule = test.get("fixed_rule", {})
    if sum(rule.get(k, -1) for k in ("tn", "fp", "fn", "tp")) != split["test_windows"]:
        raise ValueError("Rule baseline counts mismatch")
    scenarios = test.get("attack_scenarios", {})
    if not isinstance(scenarios, dict) or len(scenarios) != 3:
        raise ValueError("Attack scenario results are incomplete")
    if sum(v["total"] for v in scenarios.values()) != split["test_attack"]:
        raise ValueError("Attack scenario sample count mismatch")
    if sum(v["detected"] for v in scenarios.values()) != test["isolation_forest"]["tp"]:
        raise ValueError("Per-scenario detected counts mismatch")
    return data


def load_public_metrics(path: Path = DATA_FILE) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError("Public aggregate metrics file was not deployed")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Public metrics must be an object")
    return validate_public_metrics(data)
