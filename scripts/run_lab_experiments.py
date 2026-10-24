"""Generate a larger *local-only* lab dataset using the Step 2-4 pipeline.

Runs are separate simulated sessions. This script never reaches remote hosts:
the replay function validates loopback destinations and disallows redirects.
Output is experimental telemetry, not evidence of real-world intrusion detection.
"""
from __future__ import annotations

import argparse
import json
import random
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib import request

from scripts.attack_replay import replay_attack, validate_local_target, NoRedirectHandler

SCENARIOS = ("benign", "brute-force", "scan", "mixed")


def generate_plan(runs_per_class: int, seed: int) -> list[dict[str, object]]:
    """Predefine a balanced, varied and reproducible plan (not model labels)."""
    if not 15 <= runs_per_class <= 100:
        raise ValueError("runs_per_class must be between 15 and 100")
    rng = random.Random(seed)
    plan: list[dict[str, object]] = []
    for label in SCENARIOS:
        for i in range(runs_per_class):
            # All RFC 5737 documentation addresses; not actual external targets.
            source_ip = f"198.51.100.{1 + ((i * 7 + rng.randrange(200)) % 240)}"
            attempts = rng.randint(4, 30) if label != "scan" else 8
            plan.append({
                "scenario": label,
                "source_ip": source_ip,
                "attempts": attempts,
                "concurrency": rng.randint(1, 4),
            })
    rng.shuffle(plan)
    return plan


def check_proxy(base_url: str) -> None:
    validate_local_target(base_url)
    url = base_url.rstrip("/") + "/health"
    # No redirects or proxy environment variables, even for the health check.
    opener = request.build_opener(request.ProxyHandler({}), NoRedirectHandler())
    with opener.open(url, timeout=5) as response:
        if response.status != 200 or not response.headers.get("X-CyberSentinel-Request-ID"):
            raise RuntimeError("NGINX lab must return HTTP 200 and X-CyberSentinel-Request-ID")


def generate_dataset(
    repo_root: Path, *, runs_per_class: int = 40, seed: int = 42,
    base_url: str = "http://127.0.0.1:8080", window_seconds: int = 60,
    access_log: Path | None = None,
) -> dict[str, object]:
    if not 10 <= window_seconds <= 3600:
        raise ValueError("window_seconds must be 10..3600")
    plan = generate_plan(runs_per_class, seed)
    check_proxy(base_url)
    from scripts.collector import CollectorConfig, JsonlRotator, process_stream
    from scripts.etl import iter_events, write_csv
    from scripts.build_labeled_dataset import join_labels
    from scripts.build_window_features import build_windows
    tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:6]
    output_dir = repo_root / "simulations" / "runtime" / "processed" / f"step5_{tag}"
    output_dir.mkdir(parents=True, exist_ok=False)
    manifest = output_dir / "labels.jsonl"
    log_file = access_log or repo_root / "simulations" / "runtime" / "logs" / "access.log"
    summary_counts: Counter[str] = Counter()
    total_requests = 0
    for index, entry in enumerate(plan, 1):
        result = replay_attack(
            base_url=base_url, scenario=str(entry["scenario"]),
            source_ip=str(entry["source_ip"]), attempts=int(entry["attempts"]),
            concurrency=int(entry["concurrency"]), timeout=3.0, delay_ms=0,
            manifest_path=manifest,
        )
        if int(result["labeled_requests"]) != int(result["total_requests"]):
            raise RuntimeError("Incomplete run; refusing to continue")
        expected = {
            "benign": {"200"}, "brute-force": {"401"},
            "scan": {"404"}, "mixed": {"401", "404"},
        }[str(entry["scenario"])]
        if set(result["statuses"]) != expected:
            raise RuntimeError(
                f"Unexpected HTTP outcomes for {entry['scenario']}: {result['statuses']}. "
                "Check the local demo and NGINX logs; aborting data generation."
            )
        summary_counts[str(entry["scenario"])] += 1
        total_requests += int(result["total_requests"])
        if index % 20 == 0:
            print(f"Finished {index}/{len(plan)} local simulation runs", flush=True)

    raw_dir = output_dir / "raw"
    config = CollectorConfig(
        input_path=log_file, output_dir=raw_dir,
        target_service="webapp", schema_version="traffic_event.v1",
        rotate_bytes=5_000_000, follow=False, poll_interval=0.5,
    )
    writer = JsonlRotator(raw_dir, "webapp", 5_000_000)
    try:
        with log_file.open("r", encoding="utf-8") as handle:
            raw_events = process_stream(handle, config, writer)
    finally:
        writer.close()
    event_file = output_dir / "events.csv"
    write_csv(iter_events(raw_dir), event_file)
    label_summary = join_labels(event_file, manifest, output_dir / "labeled.csv", strict=True)
    if label_summary["matched_labeled_events"] != total_requests:
        raise RuntimeError("Manifest does not match the replay request count")
    feature_summary = build_windows(output_dir / "labeled.csv", output_dir / "window_features.csv", window_seconds)
    summary = {
        "purpose": "controlled-local-simulation-only",
        "seed": seed,
        "runs_per_class": runs_per_class,
        "runs": dict(summary_counts),
        "simulation_requests": total_requests,
        "collector_events_including_prior_logs": raw_events,
        "label_join": label_summary,
        "feature_engineering": feature_summary,
        "output_dir": str(output_dir),
    }
    (output_dir / "data_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Create labeled feature windows from bounded localhost-only simulations")
    parser.add_argument("--runs-per-class", type=int, default=40)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--window-seconds", type=int, default=60)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    args = parser.parse_args()
    try:
        report = generate_dataset(Path(__file__).resolve().parents[1], runs_per_class=args.runs_per_class,
                                  seed=args.seed, window_seconds=args.window_seconds, base_url=args.base_url)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(2, f"Step 5 lab generation failed: {exc}\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
