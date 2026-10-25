"""Fail closed on unsafe changes to offline durable watcher scope."""
from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = ('cybersentinel_agent/continuous.py','cybersentinel_agent/state_cli.py',
            'tests/test_step33_35_delivery.py','scripts/step33_35_preflight.py',
            'scripts/step35_release.py','docs/HUONG_DAN_BUOC_33_35.md',
            'docs/STEP33_35_DELIVERY_LIMITATIONS.md')


def check(root=ROOT):
    missing = [p for p in REQUIRED if not (root/p).is_file()]
    if missing:
        return {'status': 'fail', 'missing': missing}
    source = (root/'cybersentinel_agent/continuous.py').read_text()
    cli = (root/'cybersentinel_agent/state_cli.py').read_text()
    checks = {
        'strict_key_origin_binding': 'validate_watcher_identity(origin, key)' in source and
                                     'DEMO_TOKEN.fullmatch(key)' in source and 'STAGING_TOKEN.fullmatch(key)' in source,
        'durable_atomic_cursor': 'INSERT INTO cursors' in source and 'BEGIN IMMEDIATE' in source,
        'no_silent_stale_drop': 'Explicit --confirm-loss is required' in source,
        'read_only_inspection': "'?mode=ro'" in cli and 'sqlite3.connect' in cli,
        'outbox_not_unbounded': 'MAX_QUEUE = 1000' in source,
        'release_ci': 'python -m scripts.step35_release' in (root/'.github/workflows/ci.yml').read_text(),
    }
    return {'status':'pass' if all(checks.values()) else 'fail','checks': checks,
            'limits':'Offline local rehearsal; no cloud or uninterrupted 5+ minute outage recovery.'}


def main():
    result=check()
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0 if result['status']=='pass' else 2

if __name__=='__main__':
    raise SystemExit(main())
