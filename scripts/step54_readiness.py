"""Step 54: honest NO-GO evidence inventory for a CI-only rehearsal.

A static preflight does not establish real PostgreSQL CI success, Auth0 secret
custody, deploy safety, recovery RTO/RPO or independently reviewed security.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    'scripts/step52_credential_custody.py',
    'scripts/step53_cutover_drill.py',
    'scripts/step54_readiness.py',
    'scripts/install_step52_54.py',
    'tests/test_step52_54_offline.py',
    'tests/test_step52_54_pg.py',
    'docs/STEP52_54_SECURITY.md',
    'docs/HUONG_DAN_BUOC_52_54.md',
)


def assess(root: Path = ROOT) -> dict:
    missing = [p for p in REQUIRED if not (root / p).is_file()]
    workflow = root / '.github/workflows/ci.yml'
    ci = workflow.read_text(encoding='utf-8') if workflow.is_file() else ''
    hosted = root / 'hosted_api/postgres.py'
    legacy = hosted.read_text(encoding='utf-8') if hosted.is_file() else ''
    checks = {
        'source_and_tests_present': not missing,
        'offline_ci_registered': 'test_step52_54_offline.py -v' in ci,
        'pg_ci_registered': 'test_step52_54_pg.py -v' in ci,
        'isolated_pg_guard_in_ci': "CYBERSENTINEL_ISOLATED_PG_CI: '1'" in ci,
        'previous_ci_suite_kept': 'test_step49_51_pg.py -v' in ci,
        'shared_runtime_risk_disclosed': "set_config('cs.actor_id'" in legacy,
    }
    return {
        'status': 'ready_for_ci_review' if all(checks.values()) else 'incomplete',
        'missing': missing,
        'checks': checks,
        'ci_pg_tests_passed': 'unverified_in_local_preflight',
        'managed_secret_vault': False,
        'production_oidc_broker': False,
        'staging_migrated': False,
        'live_cutover_or_restore_tested': False,
        'independent_security_review': False,
        'public_beta_allowed': False,
        'decision': 'NO_GO',
        'required_next': [
            'Verify all GitHub Actions jobs including real Step 52-54 PostgreSQL tests',
            'Independently review production identity-to-role and secret custody architecture',
            'Prove per-tenant revocation, concurrency and recovery with realistic load',
            'Perform documented staging cutover and backup/restore in an authorized environment',
            'Obtain independent security review before limited beta',
        ],
    }


def main() -> int:
    result = assess()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['status'] == 'ready_for_ci_review' and not result['public_beta_allowed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
