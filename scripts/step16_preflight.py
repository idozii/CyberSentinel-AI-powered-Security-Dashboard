"""Static only - refuse to imply remote database/IdP is production ready."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    'hosted_api/__init__.py', 'hosted_api/settings.py', 'hosted_api/identity.py',
    'hosted_api/postgres.py', 'hosted_api/main.py',
    'hosted_api/migrations/001_initial.sql',
    'scripts/step16_migrate.py', 'tests/test_step16_hosted.py',
    'tests/test_step16_postgres.py', 'requirements-hosted.txt',
    'docs/HUONG_DAN_BUOC_16.md', 'docs/STEP16_DATABASE_IDENTITY_SECURITY.md',
)


def check(root: Path = ROOT):
    missing = [p for p in FILES if not (root / p).is_file()]
    if missing:
        return {'status':'fail','missing':missing}
    sql = (root / 'hosted_api/migrations/001_initial.sql').read_text()
    api = (root / 'hosted_api/main.py').read_text()
    deps = (root / 'requirements-hosted.txt').read_text()
    checks = {
        'two_rls_tables': sql.count('ENABLE ROW LEVEL SECURITY') == 2,
        'two_force_rls_tables': sql.count('FORCE ROW LEVEL SECURITY') == 2,
        'checks_writes': sql.count('WITH CHECK') == 2,
        'runtime_not_admin': 'TO cybersentinel_runtime' in sql and 'runtime role' in (root / 'hosted_api/postgres.py').read_text().lower(),
        'no_web_signup': '/hosted/v1/register' not in api and '/owner/register' not in api,
        'localhost_only': 'local_only' in api and "['127.0.0.1','localhost','testserver']" in api,
        'patched_pyjwt': 'PyJWT[crypto]>=2.13.0' in deps,
        'no_legacy_sqlite_modifications': (root / 'owner_api/store.py').is_file(),
    }
    return {'status':'pass' if all(checks.values()) else 'fail', 'checks':checks,
            'note':'Source preflight only. Does not assess external IdP, database TLS or VPS hardening.'}


def main():
    result = check()
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
