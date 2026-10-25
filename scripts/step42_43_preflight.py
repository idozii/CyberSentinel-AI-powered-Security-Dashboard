"""Fail-closed static checks for isolated tenant role adapter and CI."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    'scripts/step41_role_boundary.py', 'scripts/step42_isolated_repository.py',
    'scripts/step43_migration_plan.py', 'scripts/step42_43_preflight.py',
    'scripts/step42_43_release.py', 'tests/test_step42_43_offline.py',
    'tests/test_step42_43_pg.py', 'docs/HUONG_DAN_BUOC_42_43.md',
    'docs/STEP42_43_SECURITY.md', '.github/workflows/ci.yml',
)


def check(root: Path = ROOT) -> dict:
    missing = [p for p in REQUIRED if not (root / p).is_file()]
    if missing:
        return {'status': 'fail', 'missing': missing}
    src = (root/'scripts/step41_role_boundary.py').read_text()
    repo = (root/'scripts/step42_isolated_repository.py').read_text()
    ci = (root/'.github/workflows/ci.yml').read_text()
    checks = {
        'psycopg_cursor_executemany_not_connection': 'with conn.cursor() as cur:' in src
            and src.count('cur.executemany(') == 2 and 'conn.executemany(' not in src,
        'ci_only_db_guard': 'protected_ci(self.admin_dsn)' in repo,
        'session_user_checked': 'SELECT session_user, current_user' in repo,
        'identity_not_selected_by_request': "self.fixture.owners[self.index]" in repo,
        'offline_ci_checks': 'test_step42_43_offline.py -v' in ci,
        'pg_isolated_ci_checks': 'test_step42_43_pg.py -v' in ci
            and "CYBERSENTINEL_ISOLATED_PG_CI: '1'" in ci,
        'existing_migrations_untouched': (root/'hosted_api/migrations/001_initial.sql').exists()
            and (root/'hosted_api/migrations/002_monitoring.sql').exists(),
    }
    return {'status': 'pass' if all(checks.values()) else 'fail', 'checks': checks,
            'scope': 'CI-only role-bound prototype; shared staging runtime remains unsafe if credential is compromised'}


def main() -> int:
    result = check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
