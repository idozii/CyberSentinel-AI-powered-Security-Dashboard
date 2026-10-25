"""Fail-closed, read-only security review gate for Steps 44-45.

Passing this gate never authorizes production or public multi-tenancy.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def assess(root: Path = ROOT) -> dict:
    files = (
        'scripts/step44_tenant_lifecycle.py',
        'scripts/step45_security_gate.py',
        'scripts/install_step44_45.py',
        'tests/test_step44_45_offline.py',
        'tests/test_step44_45_pg.py',
        'docs/STEP44_45_SECURITY.md',
        'docs/HUONG_DAN_BUOC_44_45.md',
    )
    present = all((root / name).is_file() for name in files)
    ci_path = root / '.github/workflows/ci.yml'
    old_path = root / 'hosted_api/postgres.py'
    prototype_path = root / 'scripts/step41_role_boundary.py'
    ci = ci_path.read_text(encoding='utf-8') if ci_path.exists() else ''
    old = old_path.read_text(encoding='utf-8') if old_path.exists() else ''
    prototype = (prototype_path.read_text(encoding='utf-8')
                 if prototype_path.exists() else '')
    checks = {
        'patch_files_present': present,
        'offline_ci_registered': 'test_step44_45_offline.py -v' in ci,
        'postgres_ci_registered': 'test_step44_45_pg.py -v' in ci,
        'postgres_ci_disposable_guard': "CYBERSENTINEL_ISOLATED_PG_CI: '1'" in ci,
        'prototype_role_per_tenant': 'session_user' in prototype,
        'shared_runtime_not_migrated': "set_config('cs.actor_id'" in old,
        'baseline_migrations_present': all(
            (root / name).exists() for name in (
                'hosted_api/migrations/001_initial.sql',
                'hosted_api/migrations/002_monitoring.sql')),
    }
    return {
        'status': 'ready_for_ci_review' if all(checks.values()) else 'incomplete',
        'checks': checks,
        'public_beta_allowed': False,
        'staging_migrated': False,
        'credential_broker_implemented': False,
        'existing_session_revocation_proven': False,
        'rollback': 'Revert the application patch; no database migration is part of Steps 44-45.',
        'next': 'Verify disposable PG CI, design trusted identity broker, rehearse cs.* migration and full rollback before beta.',
    }


def main() -> int:
    report = assess()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['status'] == 'ready_for_ci_review' and not report['public_beta_allowed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
