"""Offline, read-only release gate for an isolated migration rehearsal.

A passing *offline* review never establishes a passing PG integration run and
never authorizes staging deployment or public beta.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    'scripts/step46_trusted_binding.py',
    'scripts/step47_schema_rehearsal.py',
    'scripts/step48_release_gate.py',
    'scripts/install_step46_48.py',
    'tests/test_step46_48_offline.py',
    'tests/test_step46_48_pg.py',
    'docs/STEP46_48_SECURITY.md',
    'docs/HUONG_DAN_BUOC_46_48.md',
    'hosted_api/migrations/001_initial.sql',
    'hosted_api/migrations/002_monitoring.sql',
)


def assess(root: Path = ROOT) -> dict:
    missing = [n for n in REQUIRED if not (root / n).is_file()]
    ci_file = root / '.github/workflows/ci.yml'
    ci = ci_file.read_text(encoding='utf-8') if ci_file.is_file() else ''
    postgres = root / 'hosted_api/postgres.py'
    old = postgres.read_text(encoding='utf-8') if postgres.is_file() else ''
    checks = {
        'required_files_present': not missing,
        'offline_test_registered': 'test_step46_48_offline.py -v' in ci,
        'postgres_test_registered': 'test_step46_48_pg.py -v' in ci,
        'postgres_guarded': "CYBERSENTINEL_ISOLATED_PG_CI: '1'" in ci,
        'shared_runtime_not_replaced': "set_config('cs.actor_id'" in old,
    }
    return {
        'status': 'ready_for_disposable_ci' if all(checks.values()) else 'incomplete',
        'checks': checks,
        'missing': missing,
        'ci_postgres_tests_verified': False,
        'auth0_production_broker_integrated': False,
        'staging_migrated': False,
        'public_beta_allowed': False,
        'next': 'Run PostgreSQL 17 isolated integration in GitHub Actions; then design reviewed credential custody and canary cutover.',
    }


def main() -> int:
    result = assess()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['status'] == 'ready_for_disposable_ci' else 2


if __name__ == '__main__':
    raise SystemExit(main())
