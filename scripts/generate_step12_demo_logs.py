"""Generate short synthetic NGINX JSONL for local Step 12 alert demonstration.

No targets, network calls, credentials, or real identities. Output is ignored by Git.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import uuid
from pathlib import Path

SCENARIOS = {
    "failed-login": (6, "/login", "POST", 401),
    "missing-pages": (8, "/not-found", "GET", 404),
    "server-errors": (5, "/api/status", "GET", 503),
}
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "simulations/runtime/owner/step12_demo_nginx.jsonl"


def generate_rows(scenario: str, timestamp: str | None = None) -> list[dict]:
    if scenario not in SCENARIOS:
        raise ValueError("Unknown local demonstration scenario")
    count, uri, method, code = SCENARIOS[scenario]
    now = timestamp or dt.datetime.now(dt.timezone.utc).isoformat()
    return [{"time_iso8601": now, "remote_addr": "198.51.100.7",
             "request_method": method, "uri": uri, "status": str(code),
             "request_time": "0.015", "request_length": "140", "bytes_sent": "220",
             "request_id": uuid.uuid4().hex} for _ in range(count)]


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic localhost-only NGINX JSON logs")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="failed-login")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    output = args.output.resolve()
    permitted = (ROOT / "simulations/runtime/owner").resolve()
    if not output.is_relative_to(permitted):
        parser.error("Output must be under simulations/runtime/owner")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for row in generate_rows(args.scenario):
            handle.write(json.dumps(row) + "\n")
    print(f"Generated {SCENARIOS[args.scenario][0]} synthetic events: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
