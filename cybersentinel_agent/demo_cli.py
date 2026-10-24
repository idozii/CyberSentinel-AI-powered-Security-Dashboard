"""Installable localhost-only demo agent: explicit dry run and one-shot send.

Never writes a key, request body, raw IP, or telemetry to stdout.
This command is not a daemon and provides no durable offline queue.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from cybersentinel_agent.client import AgentError, MAX_LINE_BYTES, send_events, to_minimal_event

DEMO_URL = 'http://127.0.0.1:8019'


def load_demo_events(input_file: Path, key: str, max_events: int = 100) -> list[dict]:
    """Validate the entire small bounded file before sending any HTTP batch."""
    if not 1 <= max_events <= 100:
        raise AgentError('max_events must be 1..100')
    rows = []
    with input_file.open('rb') as stream:
        for line in stream:
            if len(line) > MAX_LINE_BYTES:
                raise AgentError('NGINX line exceeds 8 KB')
            if not line.strip():
                continue
            if len(rows) >= max_events:
                raise AgentError('Demo log exceeds the configured event limit')
            try:
                row = json.loads(line)
            except (UnicodeError, ValueError) as exc:
                raise AgentError('Invalid JSONL') from exc
            rows.append(to_minimal_event(row, key))
    if not rows:
        raise AgentError('No suitable NGINX JSONL events found')
    return rows


def run(input_file: Path, domain_id: str, key: str, *, dry_run: bool = False,
        max_events: int = 100) -> dict:
    if not key.startswith('csd_') or len(key) < 36:
        raise AgentError('Use a local demo key (csd_) from port 8019')
    rows = load_demo_events(input_file, key, max_events)
    if dry_run:
        return {'mode': 'local-demo', 'dry_run': True, 'events_validated': len(rows),
                'transmitted': False}
    totals = {'accepted': 0, 'duplicates': 0, 'alerts_updated': 0}
    # Safe retry uses deterministic HMAC event IDs derived from request_id+stamp.
    # No local durable outbox; partial network failure requires operator replay.
    for index in range(0, len(rows), 25):
        result = send_events(DEMO_URL, domain_id, rows[index:index + 25], key)
        for field in totals:
            totals[field] += result[field]
    return {'mode': 'local-demo', 'dry_run': False, 'submitted': len(rows), **totals}


def main() -> int:
    p = argparse.ArgumentParser(description='CyberSentinel safe localhost demo one-shot agent')
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--domain-id', required=True)
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('--max-events', type=int, default=100)
    args = p.parse_args()
    try:
        result = run(args.input, args.domain_id,
                     os.environ.get('CYBERSENTINEL_AGENT_KEY', ''), dry_run=args.dry_run,
                     max_events=args.max_events)
    except (AgentError, OSError) as exc:
        p.exit(2, f'Demo agent error: {exc}\n')
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
