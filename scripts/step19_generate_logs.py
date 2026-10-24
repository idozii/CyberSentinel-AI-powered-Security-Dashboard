"""Create synthetic NGINX JSONL for isolated Step 19 demo; never real traffic."""
from __future__ import annotations

import argparse
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

SCENARIOS = {'login': (5, '/login', 401), '404': (8, '/missing', 404),
             '5xx': (5, '/api/test', 503), 'traffic': (40, '/api/test', 200)}


def generate(scenario: str, *, now: datetime | None = None) -> list[dict]:
    if scenario not in SCENARIOS:
        raise ValueError('Unknown synthetic scenario')
    count, path, status = SCENARIOS[scenario]
    moment = now or datetime.now(timezone.utc)
    timestamp = moment.isoformat(timespec='seconds')
    return [dict(time_iso8601=timestamp, request_method='GET', uri=path,
                 remote_addr='192.0.2.44', request_id=secrets.token_hex(12),
                 status=status, request_time='0.003', request_length=120,
                 bytes_sent=64) for _ in range(count)]


def main() -> int:
    parser = argparse.ArgumentParser(description='Generate synthetic NGINX JSONL for Step 19 only')
    parser.add_argument('--scenario', choices=sorted(SCENARIOS), default='login')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    # No automatic writes inside repository or overwrite of any existing log.
    target = args.output.expanduser().resolve()
    if target.exists():
        parser.error('Output already exists; choose a new filename')
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('x', encoding='utf-8') as handle:
        for event in generate(args.scenario):
            handle.write(json.dumps(event, separators=(',', ':')) + '\n')
    print(json.dumps({'synthetic': True, 'scenario': args.scenario,
                      'events': SCENARIOS[args.scenario][0], 'file': str(target)}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
