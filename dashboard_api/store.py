"""Bounded, read-only access to locally generated Step 5/6 experiment artifacts.

Never follow a user-provided filesystem path. The only client selector is a
validated run directory name. No serialized ML model is loaded here.
"""
from __future__ import annotations

import csv
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

from scripts.model_features import WINDOW_MODEL_INPUT_COLUMNS

MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_CSV_ROWS = 20_000
RUN_PATTERN = re.compile(r"^step5_[A-Za-z0-9_-]{8,80}$")
WINDOW_FIELDS = (
    "window_start", "window_end", "window_seconds", "service", "source_ip",
    "simulation_run_id", "scenario_label", "label_source", *WINDOW_MODEL_INPUT_COLUMNS,
)
PREDICTION_FIELDS = (
    "partition", "simulation_run_id", "true_label", "anomaly_score",
    "isolation_forest_pred", "rule_baseline_pred",
)
METRIC_FIELDS = (
    "status", "seed", "target_benign_validation_fpr",
    "threshold_from_benign_validation_only", "features",
    "training_benign_windows", "splits", "limitations", "versions",
)
ROBUSTNESS_FIELDS = ("status", "split_integrity", "reference_original_test", "what_if_cases", "limitations")


class ArtifactError(ValueError):
    """An artifact does not satisfy the API's bounded read contract."""


class ArtifactStore:
    def __init__(self, runs_root: Path):
        self.runs_root = Path(runs_root).resolve()

    def _run(self, run_id: str) -> Path:
        if not RUN_PATTERN.fullmatch(run_id):
            raise ArtifactError("Invalid experiment ID")
        folder = (self.runs_root / run_id).resolve()
        if not folder.is_relative_to(self.runs_root) or not folder.is_dir():
            raise FileNotFoundError("Experiment not found")
        return folder

    def _file(self, folder: Path, relative: str) -> Path:
        file = (folder / relative).resolve()
        if not file.is_relative_to(folder):
            raise ArtifactError("Artifact resolves outside experiment folder")
        if not file.is_file():
            raise FileNotFoundError("Artifact not available")
        if file.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ArtifactError("Artifact exceeds maximum permitted size")
        return file

    def _json(self, folder: Path, relative: str) -> dict[str, Any]:
        path = self._file(folder, relative)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise ArtifactError("Invalid artifact JSON") from exc
        if not isinstance(data, dict):
            raise ArtifactError("Expected JSON object")
        return data

    def _csv(self, folder: Path, relative: str, required: tuple[str, ...]) -> list[dict[str, str]]:
        path = self._file(folder, relative)
        try:
            with path.open("r", encoding="utf-8", newline="") as handle:
                reader = csv.DictReader(handle)
                header = reader.fieldnames or []
                if not set(required).issubset(header):
                    raise ArtifactError("Missing required artifact CSV columns")
                rows = []
                for row in reader:
                    if len(rows) >= MAX_CSV_ROWS:
                        raise ArtifactError("Artifact has too many rows")
                    if None in row:
                        raise ArtifactError("Malformed CSV row")
                    rows.append(row)
                return rows
        except UnicodeError as exc:
            raise ArtifactError("Invalid artifact CSV encoding") from exc

    def list_runs(self) -> list[dict[str, object]]:
        if not self.runs_root.exists():
            return []
        output = []
        # Scan only immediate entries; no recursive directory walking.
        for candidate in sorted(self.runs_root.iterdir(), key=lambda p: p.name, reverse=True):
            if not RUN_PATTERN.fullmatch(candidate.name):
                continue
            try:
                folder = self._run(candidate.name)
                if not (folder / "window_features.csv").is_file():
                    continue
                output.append({
                    "run_id": folder.name,
                    "has_metrics": (folder / "ml_results" / "metrics.json").is_file(),
                    "has_robustness": (folder / "ml_results" / "robustness_report.json").is_file(),
                })
            except (FileNotFoundError, ArtifactError):
                continue
            if len(output) >= 100:
                break
        return output

    def summary(self, run_id: str) -> dict[str, Any]:
        folder = self._run(run_id)
        data = self._json(folder, "data_summary.json")
        join = data.get("label_join", {})
        feature = data.get("feature_engineering", {})
        if not isinstance(join, dict) or not isinstance(feature, dict):
            raise ArtifactError("Invalid summary structure")
        fields = {
            "run_id": run_id,
            "purpose": data.get("purpose"),
            "seed": data.get("seed"),
            "runs_per_class": data.get("runs_per_class"),
            "runs": data.get("runs", {}),
            "simulation_requests": data.get("simulation_requests"),
            "matched_labeled_events": join.get("matched_labeled_events"),
            "unlabeled_events": join.get("unlabeled_events"),
            "manifest_records_without_event": join.get("manifest_records_without_event"),
            "windows": feature.get("windows"),
            "window_seconds": feature.get("window_seconds"),
            "window_label_counts": feature.get("window_label_counts", {}),
            "model_feature_columns": feature.get("model_feature_columns", []),
        }
        if fields["purpose"] != "controlled-local-simulation-only":
            raise ArtifactError("Dataset is not an explicitly marked local simulation")
        return fields

    def windows(self, run_id: str, *, limit: int = 500, scenario: str | None = None) -> dict[str, Any]:
        folder = self._run(run_id)
        rows = self._csv(folder, "window_features.csv", WINDOW_FIELDS)
        counts: Counter[str] = Counter()
        results = []
        for row in rows:
            label = row["scenario_label"]
            if label not in {"simulated_benign", "simulated_brute_force", "simulated_path_scan", "simulated_mixed_attack"}:
                raise ArtifactError("Unrecognized simulated scenario label")
            if row["label_source"] != "controlled_simulation":
                raise ArtifactError("Window does not carry a trusted simulation label")
            counts[label] += 1
            if scenario is not None and label != scenario:
                continue
            if len(results) < limit:
                record: dict[str, Any] = {k: row[k] for k in WINDOW_FIELDS if k not in WINDOW_MODEL_INPUT_COLUMNS}
                for field in WINDOW_MODEL_INPUT_COLUMNS:
                    try:
                        n = float(row[field])
                    except (TypeError, ValueError) as exc:
                        raise ArtifactError(f"Invalid numeric feature {field}") from exc
                    if not math.isfinite(n) or n < 0:
                        raise ArtifactError(f"Non-finite or negative feature {field}")
                    record[field] = n
                results.append(record)
        return {"run_id": run_id, "total_windows": len(rows), "label_counts": dict(counts), "returned": len(results), "rows": results}

    def metrics(self, run_id: str) -> dict[str, Any]:
        document = self._json(self._run(run_id), "ml_results/metrics.json")
        if not isinstance(document.get("splits"), dict):
            raise ArtifactError("Model metrics missing split evaluation")
        return {k: document[k] for k in METRIC_FIELDS if k in document}

    def predictions(self, run_id: str, *, limit: int = 500, partition: str | None = None) -> dict[str, Any]:
        rows = self._csv(self._run(run_id), "ml_results/predictions.csv", PREDICTION_FIELDS)
        result = []
        for row in rows:
            if row["partition"] not in ("validation", "test"):
                raise ArtifactError("Invalid prediction partition")
            if partition is not None and row["partition"] != partition:
                continue
            if len(result) < limit:
                try:
                    score = float(row["anomaly_score"])
                    predicted = int(row["isolation_forest_pred"])
                    rule = int(row["rule_baseline_pred"])
                except (ValueError, TypeError) as exc:
                    raise ArtifactError("Invalid prediction score or decision") from exc
                if not math.isfinite(score) or predicted not in (0, 1) or rule not in (0, 1):
                    raise ArtifactError("Invalid prediction values")
                result.append({**{k: row[k] for k in ("partition", "simulation_run_id", "true_label")},
                               "anomaly_score": score,
                               "isolation_forest_pred": predicted,
                               "rule_baseline_pred": rule})
        return {"run_id": run_id, "total_predictions": len(rows), "returned": len(result), "rows": result}

    def robustness(self, run_id: str) -> dict[str, Any]:
        doc = self._json(self._run(run_id), "ml_results/robustness_report.json")
        return {k: doc[k] for k in ROBUSTNESS_FIELDS if k in doc}
