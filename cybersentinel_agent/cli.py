"""Run once on a trusted local NGINX JSONL file. No remote endpoints allowed."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from cybersentinel_agent.client import AgentError, load_events, send_events


def main() -> int:
    p = argparse.ArgumentParser(description="CyberSentinel local development telemetry agent")
    p.add_argument("--input", required=True, type=Path, help="NGINX JSON access log, one line per event")
    p.add_argument("--domain-id", required=True, help="ID of a DNS-verified domain")
    p.add_argument("--server", default="http://127.0.0.1:8002")
    p.add_argument("--max-events", type=int, default=25)
    args = p.parse_args()
    key = os.environ.get("CYBERSENTINEL_AGENT_KEY", "")
    if not key:
        p.error("Set CYBERSENTINEL_AGENT_KEY through the environment; do not put keys in commands")
    try:
        rows = load_events(args.input, key, args.max_events)
        if not rows:
            p.error("No NGINX events found")
        response = send_events(args.server, args.domain_id, rows, key)
    except (AgentError, OSError) as exc:
        p.exit(2, f"Agent failed: {exc}\n")
    print(json.dumps({"mode": "local-demo", "submitted": len(rows), **response}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
