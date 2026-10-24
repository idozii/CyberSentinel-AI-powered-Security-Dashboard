"""Self-contained in-process smoke test of the local portfolio MVP.

No domain, Neon, Auth0, live traffic, secrets on disk or bound socket needed.
The one-time fake csd_ token stays only in process memory.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from fastapi.testclient import TestClient

from cybersentinel_agent.client import to_minimal_event
from hosted_api.local_demo import DemoStore, create_demo_app
from scripts.step19_generate_logs import generate
from scripts.step21_quality_gate import quality_gate
from scripts.step24_failure_analysis import analyze


def release_smoke() -> dict:
    db = DemoStore()
    client = TestClient(create_demo_app(db, enabled=True), follow_redirects=False)
    token = db.issue_key()
    payload = {'domain_id': db.domain_id.hex,
               'events': [to_minimal_event(row, token) for row in generate('login')]}
    headers = {'Authorization': 'Bearer ' + token}
    try:
        health = client.get('/health')
        first = client.post('/agent/v1/ingest', json=payload, headers=headers)
        second = client.post('/agent/v1/ingest', json=payload, headers=headers)
        root = client.get('/')
        triage = client.get('/demo/alerts?status=open&severity=high')
        alert_id = db.snapshot()['alerts'][0]['id']
        detail = client.get('/demo/alerts/' + alert_id)
        csrf = root.cookies.get('demo_csrf', '')
        acknowledged = client.post('/demo/ack/' + alert_id, data={'_csrf': csrf},
                                   headers={'Origin': 'http://127.0.0.1:8019'})
        after = client.get('/demo/alerts?status=acknowledged')
        rotated_token = db.issue_key()
        old_key_denied = client.post('/agent/v1/ingest', json=payload, headers=headers)
        assert rotated_token != token
        quality = quality_gate()
        robustness = analyze()
        checks = {
            'isolated_health': health.status_code == 200 and health.json()['public'] is False,
            'first_ingest': first.status_code == 200 and first.json()['accepted'] == 5 and first.json()['alerts_updated'] == 1,
            'replay_dedup': second.status_code == 200 and second.json()['duplicates'] == 5 and second.json()['alerts_updated'] == 0,
            'operator_triage': triage.status_code == 200 and 'Repeated login failures' in triage.text,
            'aggregate_evidence': detail.status_code == 200 and 'Events in evidence window: 5' in detail.text,
            'acknowledge': acknowledged.status_code == 200 and after.status_code == 200 and 'Matching alerts: 1' in after.text,
            'key_rotation': old_key_denied.status_code == 401,
            'step21_baseline_gate': quality['status'] == 'pass',
            'step24_fixture_suite': robustness['scenario_count'] == 11,
        }
        return {'status': 'pass' if all(checks.values()) else 'fail',
                'checks': checks, 'steps_covered': [22, 23, 24, 25],
                'limitations': ['In-process synthetic smoke only - not a browser, TLS, real agent daemon, PostgreSQL or cloud test.',
                                'No production accuracy, uptime or tenant safety claim.']}
    finally:
        client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description='Local portfolio MVP in-process release smoke')
    parser.add_argument('--output', type=Path, help='Write summary to new JSON file outside Git')
    args = parser.parse_args()
    result = release_smoke()
    if args.output:
        target = args.output.expanduser().resolve()
        root = Path(__file__).resolve().parents[1]
        if target == root or target.is_relative_to(root) or target.exists():
            parser.error('Output must be a new file outside the repository')
        if not target.parent.is_dir():
            parser.error('Output directory does not exist')
        target.write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
