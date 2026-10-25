"""Static, read-only checks for Steps 39-40. Never deploys anything."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NEEDED = (
    'scripts/step39_actor_boundary.py', 'scripts/step40_readiness_report.py',
    'scripts/step39_40_preflight.py', 'scripts/step39_40_release.py',
    'scripts/install_step39_40.py', 'tests/test_step39_actor_spoof_pg.py',
    'tests/test_step39_40_safety.py', 'docs/HUONG_DAN_BUOC_39_40.md',
    'docs/STEP39_40_SECURITY.md', 'docs/STEP40_RESTORE_HTTPS_RUNBOOK.md',
)


def check(root: Path = ROOT) -> dict:
    missing = [x for x in NEEDED if not (root/x).is_file()]
    if missing:
        return {'status': 'fail', 'missing': missing}
    ci = (root/'.github/workflows/ci.yml').read_text()
    actor_source = (root/'scripts/step39_actor_boundary.py').read_text()
    reporting = (root/'scripts/step40_readiness_report.py').read_text()
    checks = {
        'postgres_only_disposable_localhost': "url.hostname in ('127.0.0.1', 'localhost')" in actor_source,
        'ci_disposable_witness': 'test_step39_actor_spoof_pg.py -v' in ci and
                                  "CYBERSENTINEL_ISOLATED_PG_CI: '1'" in ci,
        'ci_local_regression': 'python -m scripts.step39_40_release' in ci,
        'report_fail_closed': "'public_beta_allowed': False" in reporting,
        'create_only_safe_output': 'os.O_EXCL' in reporting and "getattr(os, 'O_NOFOLLOW', 0)" in reporting,
        'no_prod_credentials_required': 'CYBERSENTINEL_TEST_PG_RUNTIME_DSN' not in reporting,
        'original_rls_files_present': (root/'hosted_api/migrations/001_initial.sql').is_file() and
                                      (root/'hosted_api/migrations/002_monitoring.sql').is_file(),
    }
    return {'status': 'pass' if all(checks.values()) else 'fail', 'checks': checks,
            'limitations': 'Source/CI check, not actual TLS, live backup/restore, or independent pen test.'}


def main():
    x = check()
    print(json.dumps(x, indent=2, sort_keys=True))
    return 0 if x['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
