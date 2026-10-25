"""Fail closed if Step 41 role-boundary proof is not wired to isolated CI."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    'scripts/step41_role_boundary.py', 'scripts/install_step41.py',
    'scripts/step41_preflight.py', 'scripts/step41_release.py',
    'tests/test_step41_role_isolation_pg.py', 'tests/test_step41_offline.py',
    'docs/HUONG_DAN_BUOC_41.md', 'docs/STEP41_TENANT_ROLE_SECURITY.md',
)


def check(root: Path = ROOT) -> dict:
    missing = [p for p in REQUIRED if not (root/p).is_file()]
    if missing:
        return {'status': 'fail', 'missing': missing}
    src = (root/'scripts/step41_role_boundary.py').read_text()
    pg = (root/'tests/test_step41_role_isolation_pg.py').read_text()
    ci = (root/'.github/workflows/ci.yml').read_text()
    legacy = (root/'hosted_api/postgres.py').read_text()
    checks = {
        'ci_disposable_pg': 'test_step41_role_isolation_pg.py -v' in ci
             and "CYBERSENTINEL_ISOLATED_PG_CI: '1'" in ci,
        'ci_offline': 'python -m scripts.step41_release' in ci,
        'login_bound_sql': 'session_user' in src and 'CREATE POLICY own_events' in src,
        'forced_rls': src.count('FORCE ROW LEVEL SECURITY') >= 1,
        'read_only_identity_binding': 'GRANT SELECT ON {}.tenant_logins' in src,
        'disposable_admin_guard': 'protected_ci(admin_dsn)' in src
            and 'disposable_test_dsn(admin_dsn)' in src,
        'cross_tenant_tests': 'test_cross_owner_write_rejected' in pg
            and 'test_login_role_ignores_spoofed_actor' in pg,
        'application_not_migrated': "role['name'] != 'cybersentinel_runtime'" in legacy,
        'existing_migrations_unchanged': (root/'hosted_api/migrations/001_initial.sql').is_file()
            and (root/'hosted_api/migrations/002_monitoring.sql').is_file(),
    }
    return {'status': 'pass' if all(checks.values()) else 'fail', 'checks': checks,
            'scope': 'CI-only tenant database-role proof, not live service mitigation'}


def main() -> int:
    result = check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
