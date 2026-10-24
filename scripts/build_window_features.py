"""Aggregate *trusted, labeled* HTTP events into per-run, per-IP fixed windows.

This is an educational prototype for a controlled local simulation. The
features describe request behavior; labels are only carried as evaluation
metadata and are never used to calculate numerical feature columns.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from scripts.model_features import WINDOW_MODEL_INPUT_COLUMNS
except ModuleNotFoundError:  # `python scripts/build_window_features.py ...`
    from model_features import WINDOW_MODEL_INPUT_COLUMNS

ALLOWED_LABELS = frozenset({
    "simulated_benign", "simulated_brute_force", "simulated_path_scan"
})
OUTPUT_COLUMNS = (
    "window_start", "window_end", "window_seconds", "service", "source_ip",
    "simulation_run_id", "scenario_label", "label_source",
    *WINDOW_MODEL_INPUT_COLUMNS,
)
REQUIRED = {
    "captured_at", "source_ip", "service", "request_id", "simulation_run_id",
    "scenario_label", "label_source", "http_method", "path",
    "status_code", "request_bytes", "response_bytes", "duration_ms",
    "query_present",
}


def parse_timestamp(raw: str, row_number: int) -> datetime:
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Row {row_number}: invalid captured_at: {raw!r}") from exc
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError(f"Row {row_number}: captured_at must have a timezone")
    return dt.astimezone(timezone.utc)


def nonnegative_float(raw: str, name: str, row_number: int) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Row {row_number}: invalid {name}: {raw!r}") from exc
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"Row {row_number}: {name} must be finite and nonnegative")
    return value


def status_code(raw: str, row_number: int) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Row {row_number}: invalid status_code: {raw!r}") from exc
    if not 100 <= value <= 599:
        raise ValueError(f"Row {row_number}: HTTP status out of range: {value}")
    return value


def parse_bool(raw: str, row_number: int) -> bool:
    if raw.lower() in ("true", "1"):
        return True
    if raw.lower() in ("false", "0"):
        return False
    raise ValueError(f"Row {row_number}: invalid query_present: {raw!r}")


@dataclass
class WindowAggregate:
    count: int = 0
    gets: int = 0
    posts: int = 0
    failed_logins: int = 0
    login_attempts: int = 0
    http_401: int = 0
    http_404: int = 0
    http_4xx: int = 0
    with_query: int = 0
    duration_total: float = 0
    req_bytes_total: float = 0
    resp_bytes_total: float = 0
    unique_paths: set[str] = field(default_factory=set)
    labels: set[str] = field(default_factory=set)

    def observe(self, row: dict[str, str], row_number: int) -> None:
        method = row["http_method"].upper().strip()
        path = row["path"].strip() or "/"
        code = status_code(row["status_code"], row_number)
        request_bytes = nonnegative_float(row["request_bytes"], "request_bytes", row_number)
        response_bytes = nonnegative_float(row["response_bytes"], "response_bytes", row_number)
        duration = nonnegative_float(row["duration_ms"], "duration_ms", row_number)
        has_query = parse_bool(row["query_present"].strip(), row_number)
        self.count += 1
        self.gets += int(method == "GET")
        self.posts += int(method == "POST")
        login_attempt = method == "POST" and path == "/login"
        self.login_attempts += int(login_attempt)
        self.failed_logins += int(login_attempt and code == 401)
        self.http_401 += int(code == 401)
        self.http_404 += int(code == 404)
        self.http_4xx += int(400 <= code < 500)
        self.with_query += int(has_query)
        self.duration_total += duration
        self.req_bytes_total += request_bytes
        self.resp_bytes_total += response_bytes
        self.unique_paths.add(path)
        self.labels.add(row["scenario_label"])

    def to_features(self, window_seconds: int) -> dict[str, int | float]:
        n = self.count
        return {
            "request_count": n,
            "request_rate_per_second": round(n / window_seconds, 6),
            "get_ratio": round(self.gets / n, 6),
            "post_ratio": round(self.posts / n, 6),
            "login_attempt_count": self.login_attempts,
            "failed_login_count": self.failed_logins,
            "unique_path_count": len(self.unique_paths),
            "http_401_ratio": round(self.http_401 / n, 6),
            "http_404_ratio": round(self.http_404 / n, 6),
            "http_4xx_ratio": round(self.http_4xx / n, 6),
            "query_ratio": round(self.with_query / n, 6),
            "mean_duration_ms": round(self.duration_total / n, 6),
            "mean_request_bytes": round(self.req_bytes_total / n, 6),
            "mean_response_bytes": round(self.resp_bytes_total / n, 6),
        }


def summarize_label(labels: set[str]) -> str:
    if len(labels) == 1:
        return next(iter(labels))
    # A mixed window must never be assigned to the benign class.
    return "simulated_mixed_attack"


def build_windows(input_path: Path, output_path: Path, window_seconds: int = 60) -> dict[str, Any]:
    if not 10 <= window_seconds <= 3600:
        raise ValueError("window_seconds must be between 10 and 3600")
    seen_ids: set[str] = set()
    aggregates: dict[tuple[str, str, str, int], WindowAggregate] = {}
    skipped_unlabeled = 0
    total_events = 0
    with input_path.open("r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        missing = REQUIRED - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Missing input columns: {', '.join(sorted(missing))}")
        for row_number, row in enumerate(reader, start=2):
            total_events += 1
            request_id = row["request_id"].strip()
            if not request_id:
                raise ValueError(f"Row {row_number}: missing request_id")
            if request_id in seen_ids:
                raise ValueError(f"Row {row_number}: duplicate request_id {request_id}")
            seen_ids.add(request_id)
            label = row["scenario_label"].strip()
            if label == "unlabeled" or not label:
                skipped_unlabeled += 1
                continue
            if label not in ALLOWED_LABELS or row["label_source"] != "controlled_simulation":
                raise ValueError(f"Row {row_number}: label is not a trusted simulation label")
            run = row["simulation_run_id"].strip()
            ip = row["source_ip"].strip()
            service = row["service"].strip()
            if not run or not ip or not service:
                raise ValueError(f"Row {row_number}: missing run ID, source IP or service")
            dt = parse_timestamp(row["captured_at"], row_number)
            start_epoch = (int(dt.timestamp()) // window_seconds) * window_seconds
            key = (run, ip, service, start_epoch)
            aggregates.setdefault(key, WindowAggregate()).observe(row, row_number)
    if not aggregates:
        raise ValueError("No trusted labeled events found; generate Step 3 labeled.csv first")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    staging = output_path.with_name(output_path.name + ".staging." + uuid.uuid4().hex)
    counts: Counter[str] = Counter()
    try:
        with staging.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=OUTPUT_COLUMNS)
            writer.writeheader()
            for (run, ip, service, epoch), group in sorted(aggregates.items(), key=lambda x: (x[0][3], x[0][0], x[0][1], x[0][2])):
                label = summarize_label(group.labels)
                counts[label] += 1
                start = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="seconds")
                end = datetime.fromtimestamp(epoch + window_seconds, tz=timezone.utc).isoformat(timespec="seconds")
                record = {
                    "window_start": start, "window_end": end, "window_seconds": window_seconds,
                    "service": service, "source_ip": ip,
                    "simulation_run_id": run, "scenario_label": label,
                    "label_source": "controlled_simulation",
                    **group.to_features(window_seconds),
                }
                writer.writerow(record)
        os.replace(staging, output_path)
    finally:
        staging.unlink(missing_ok=True)
    return {
        "input_events": total_events,
        "labeled_events": total_events - skipped_unlabeled,
        "skipped_unlabeled_events": skipped_unlabeled,
        "windows": len(aggregates),
        "window_seconds": window_seconds,
        "window_label_counts": dict(counts),
        "model_feature_columns": list(WINDOW_MODEL_INPUT_COLUMNS),
        "output": str(output_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build leakage-aware window features from trusted lab events")
    parser.add_argument("--input", type=Path, required=True, help="Step 3 labeled.csv")
    parser.add_argument("--output", type=Path, required=True, help="Output window_features.csv")
    parser.add_argument("--window-seconds", type=int, default=60)
    args = parser.parse_args()
    try:
        result = build_windows(args.input, args.output, args.window_seconds)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Feature engineering failed: {exc}\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
