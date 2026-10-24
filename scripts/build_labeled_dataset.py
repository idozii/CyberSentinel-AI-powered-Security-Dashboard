"""Join trusted lab simulation labels with collected HTTP events by proxy request_id.

IMPORTANT: Labels are NOT inferred from HTTP status, URL path, IP or User-Agent.
No unmatched event is assumed to be benign.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

# This file is run as `python scripts/build_labeled_dataset.py` from repo root.
VALID_LABELS = frozenset({
    "simulated_benign", "simulated_brute_force", "simulated_path_scan"
})
LABEL_COLUMNS = ("scenario_label", "label_source", "simulation_run_id")


def load_manifest(path: Path) -> dict[str, dict[str, Any]]:
    """Validate a trusted manifest; reject conflicting or duplicate request IDs."""
    lookup: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid manifest JSON at line {lineno}") from exc
            if not isinstance(item, dict):
                raise ValueError(f"Manifest line {lineno} is not an object")
            request_id = item.get("request_id")
            label = item.get("scenario_label")
            run_id = item.get("run_id")
            if not isinstance(request_id, str) or not request_id:
                raise ValueError(f"Manifest line {lineno}: missing request_id")
            if label not in VALID_LABELS:
                raise ValueError(f"Manifest line {lineno}: unrecognized scenario_label")
            if not isinstance(run_id, str) or not run_id:
                raise ValueError(f"Manifest line {lineno}: missing run_id")
            if request_id in lookup:
                raise ValueError(f"Duplicate request_id in manifest: {request_id}")
            lookup[request_id] = item
    if not lookup:
        raise ValueError("Manifest is empty")
    return lookup


def join_labels(events_csv: Path, manifest: Path, output_csv: Path, *, strict: bool = False) -> dict[str, Any]:
    """Write labeled CSV atomically and report coverage without relabeling unknowns."""
    labels = load_manifest(manifest)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    # Ensure strict failures do not leave a misleading finished output file.
    staged = output_csv.with_name(output_csv.name + f".staging.{os.getpid()}")
    matched: set[str] = set()
    observed_event_ids: set[str] = set()
    by_label: Counter[str] = Counter()
    count = 0
    try:
        with events_csv.open("r", encoding="utf-8", newline="") as reader_handle:
            reader = csv.DictReader(reader_handle)
            fieldnames = reader.fieldnames or []
            if "request_id" not in fieldnames:
                raise ValueError("Events CSV missing request_id column")
            if any(column in fieldnames for column in LABEL_COLUMNS):
                raise ValueError("Events CSV already contains labels; use original ETL events CSV")
            with staged.open("w", encoding="utf-8", newline="") as writer_handle:
                writer = csv.DictWriter(writer_handle, fieldnames=[*fieldnames, *LABEL_COLUMNS])
                writer.writeheader()
                for row in reader:
                    count += 1
                    request_id = row.get("request_id", "")
                    if not request_id:
                        raise ValueError(f"Event row {count}: missing request_id")
                    if request_id in observed_event_ids:
                        raise ValueError(
                            f"Duplicate event request_id: {request_id}. "
                            "Use one clean collector run to avoid duplicated training rows."
                        )
                    observed_event_ids.add(request_id)
                    entry = labels.get(request_id)
                    if entry is None:
                        row.update({
                            "scenario_label": "unlabeled",
                            "label_source": "none",
                            "simulation_run_id": "",
                        })
                    else:
                        row.update({
                            "scenario_label": entry["scenario_label"],
                            "label_source": "controlled_simulation",
                            "simulation_run_id": entry["run_id"],
                        })
                        matched.add(request_id)
                    by_label[row["scenario_label"]] += 1
                    writer.writerow(row)
        missing_manifest = len(labels) - len(matched)
        if strict and missing_manifest:
            raise ValueError(
                f"{missing_manifest} manifest request IDs were not found in events CSV. "
                "Verify NGINX logging and collect the correct access.log."
            )
        staged.replace(output_csv)
        return {
            "events": count,
            "matched_labeled_events": len(matched),
            "unlabeled_events": by_label.get("unlabeled", 0),
            "manifest_records_without_event": missing_manifest,
            "label_counts": dict(by_label),
            "output": str(output_csv),
        }
    finally:
        if staged.exists():
            staged.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description="Join NGINX events with a trusted simulator manifest")
    parser.add_argument("--events", type=Path, required=True, help="Unlabeled CSV from scripts/etl.py")
    parser.add_argument("--manifest", type=Path, required=True, help="Manifest from replay --manifest-path")
    parser.add_argument("--output", type=Path, required=True, help="Labeled training CSV")
    parser.add_argument("--strict", action="store_true", help="Fail unless every manifest record has a matching event")
    args = parser.parse_args()
    try:
        result = join_labels(args.events, args.manifest, args.output, strict=args.strict)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Label join failed: {exc}\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
