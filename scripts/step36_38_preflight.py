"""Check Step 36-38 source boundaries before a LOCAL release."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    'tests/test_step36_tenant_pg.py', 'tests/test_step36_38_safety.py',
    'scripts/step37_ops_report.py', 'scripts/step38_outbox_recovery.py',
    'scripts/step36_38_preflight.py', 'scripts/step36_38_release.py', 'scripts/install_step36_38.py',
    'docs/HUONG_DAN_BUOC_36_38.md', 'docs/STEP36_38_SECURITY.md',
)


def check(root: Path = ROOT) -> dict:
    absent = [p for p in FILES if not (root / p).is_file()]
    if absent:
        return {'status': 'fail', 'missing': absent}
    test_pg = (root / FILES[0]).read_text()
    backups = (root / FILES[3]).read_text()
    ci = (root / '.github/workflows/ci.yml').read_text()
    checks = {
        'pg_only_disposable_localhost': "parsed.hostname not in ('127.0.0.1', 'localhost')" in test_pg,
        'ci_real_rls_regression': 'test_step36_tenant_pg.py -v' in ci,
        'fail_closed_restore': "Explicit --confirm-restore is required" in backups,
        'backup_create_only': 'os.O_EXCL' in backups and "getattr(os, 'O_NOFOLLOW', 0)" in backups,
        'sqlite_consistency_snapshot': 'src.backup(dst)' in backups,
        'unmodified_live_migrations': (root / 'hosted_api/migrations/001_initial.sql').is_file() and
                                      (root / 'hosted_api/migrations/002_monitoring.sql').is_file(),
        'beta_still_blocked': 'python -m scripts.step30_beta_gate --expect-blocked' in ci,
        'offline_release_ci': 'python -m scripts.step36_38_release' in ci,
    }
    return {'status': 'pass' if all(checks.values()) else 'fail', 'checks': checks,
            'scope': 'Offline/CI hardening. Not penetration testing or authorized public beta.'}


def main():
    outcome = check()
    print(json.dumps(outcome, indent=2, sort_keys=True))
    return 0 if outcome['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
