"""Reproducible offline reliability/failure drill for the isolated demo.

This test deliberately uses only a fresh in-memory store and ASGI TestClient.
It must never write to Neon, use real agent keys or bind a network socket.
"""
from __future__ import annotations

import argparse
import json
import time
import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from hosted_api.local_demo import DemoStore, create_demo_app


def synthetic_events(n: int, *, stale: bool = False) -> list[dict]:
    if n < 1 or n > 125:
        raise ValueError('Out-of-range synthetic event count')
    timestamp = int(time.time()) - (601 if stale else 0)
    return [
        {'event_id': uuid.uuid4().hex, 'occurred_at': timestamp,
         'source_ref': 'a' * 32, 'method': 'GET', 'path_group': 'login',
         'status_code': 401, 'duration_ms': 1.0,
         'request_bytes': 12, 'response_bytes': 8}
        for _ in range(n)
    ]


def reliability_drill() -> dict:
    store = DemoStore()
    checks: dict[str, bool] = {}
    with TestClient(create_demo_app(store, enabled=True)) as client:
        key = store.issue_key()
        domain = store.domain_id.hex
        payload = {'domain_id': domain, 'events': synthetic_events(5)}
        headers = {'Authorization': 'Bearer ' + key}
        first = client.post('/agent/v1/ingest', json=payload, headers=headers)
        retry = client.post('/agent/v1/ingest', json=payload, headers=headers)
        checks['accepted_five'] = first.status_code == 200 and first.json()['accepted'] == 5
        checks['one_explainable_alert'] = first.status_code == 200 and first.json()['alerts_updated'] == 1
        checks['replayed_no_duplicates'] = retry.status_code == 200 and retry.json()['duplicates'] == 5
        checks['no_duplicate_alerts'] = retry.status_code == 200 and retry.json()['alerts_updated'] == 0
        bad_key = client.post('/agent/v1/ingest', json=payload,
                              headers={'Authorization': 'Bearer csd_invalid'})
        checks['wrong_key_rejected'] = bad_key.status_code == 401
        wrong_domain = client.post('/agent/v1/ingest', json={**payload, 'domain_id': uuid.uuid4().hex}, headers=headers)
        checks['wrong_domain_rejected'] = wrong_domain.status_code == 401
        stale = client.post('/agent/v1/ingest', json={'domain_id': domain, 'events': synthetic_events(1, stale=True)}, headers=headers)
        checks['stale_rejected'] = stale.status_code == 422
        huge = client.post('/agent/v1/ingest', content=b'X' * 32769, headers=headers)
        checks['oversized_rejected'] = huge.status_code == 413
        old_key = key
        new_key = store.issue_key()
        checks['rotation_invalidates_old_key'] = (
            new_key != old_key and
            client.post('/agent/v1/ingest', json=payload, headers=headers).status_code == 401)
        checks['rotation_clears_previous_telemetry'] = store.snapshot()['total_events'] == 0
        # Counters are global to this one in-memory process and never contain keys.
        ops = client.get('/demo/operations.json')
        checks['safe_operational_counters'] = (ops.status_code == 200 and
            ops.json()['counts']['invalid_credentials'] >= 2 and
            'csd_' not in ops.text and old_key not in ops.text and domain not in ops.text)
    with TestClient(create_demo_app(DemoStore(), enabled=True)) as restarted:
        checks['restart_discards_key_and_events'] = (
            restarted.get('/demo/operations.json').json()['events_in_memory'] == 0
            and restarted.post('/agent/v1/ingest', json=payload, headers={'Authorization': 'Bearer ' + new_key}).status_code == 401)
    return {'status': 'pass' if all(checks.values()) else 'fail',
            'checks': checks,
            'scope': 'offline synthetic single-process localhost demo',
            'limitations': [
                'This is not network fault injection or a durable queue test.',
                'The actual PostgreSQL ingest pipeline still requires load and recovery tests.',
                'Restart deliberately erases demo state: expected for a nonpersistent playground.',
            ]}


def main() -> int:
    parser = argparse.ArgumentParser(description='Offline synthetic failure and recovery drill')
    parser.add_argument('--output', type=Path, help='Write to a NEW file outside repository')
    args = parser.parse_args()
    report = reliability_drill()
    if args.output:
        path = args.output.expanduser().resolve()
        root = Path(__file__).resolve().parents[1]
        if path.exists() or path == root or path.is_relative_to(root) or not path.parent.is_dir():
            parser.error('Output must be a new file outside repository, within an existing directory')
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
