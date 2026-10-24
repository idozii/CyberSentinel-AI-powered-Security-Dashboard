from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, Iterable, Iterator, List


FIELDNAMES = [
    "schema_version",
    "captured_at",
    "service",
    "container_id",
    "source_ip",
    "http_method",
    "host",
    "path",
    "query_present",
    "status_code",
    "request_bytes",
    "response_bytes",
    "duration_ms",
    "user_agent",
    "referer",
    "forwarded_for",
    "request_id",
]


def iter_jsonl_files(input_dir: Path) -> Iterator[Path]:
    for path in sorted(input_dir.glob("*.jsonl")):
        if path.is_file():
            yield path


def iter_events(input_dir: Path) -> Iterator[Dict[str, object]]:
    for path in iter_jsonl_files(input_dir):
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    payload = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid JSON in {path} line {line_number}") from exc
                yield payload


def flatten_event(event: Dict[str, object]) -> Dict[str, object]:
    return {field: event.get(field, "") for field in FIELDNAMES}


def write_csv(events: Iterable[Dict[str, object]], output: Path) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        for event in events:
            writer.writerow(flatten_event(event))
            count += 1
    return count


def write_jsonl(events: Iterable[Dict[str, object]], output: Path) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with output.open("w", encoding="utf-8") as handle:
        for event in events:
            normalized = flatten_event(event)
            handle.write(json.dumps(normalized, separators=(",", ":")) + "\n")
            count += 1
    return count


def summarize_events(events: List[Dict[str, object]]) -> Dict[str, object]:
    services = sorted({str(event.get("service", "")) for event in events if event.get("service")})
    methods = sorted({str(event.get("http_method", "")) for event in events if event.get("http_method")})
    return {
        "events": len(events),
        "services": services,
        "methods": methods,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Convert collected JSONL traffic events into training artifacts.")
    parser.add_argument("--input-dir", required=True, help="Directory containing collector JSONL files.")
    parser.add_argument("--output", required=True, help="Output file path.")
    parser.add_argument("--format", choices=("csv", "jsonl"), default="csv", help="Output format.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    input_dir = Path(args.input_dir)
    output = Path(args.output)
    events = list(iter_events(input_dir))

    if args.format == "csv":
        count = write_csv(events, output)
    else:
        count = write_jsonl(events, output)

    summary = summarize_events(events)
    print(json.dumps({"written_events": count, **summary}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
