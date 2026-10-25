"""Source-only security review inventory. Always NO-GO for real multi-tenant beta."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    'hosted_api/tenant_session_boundary.py',
    'scripts/step56_boundary_canary.py',
    'scripts/step57_architecture_gate.py',
    'scripts/install_step55_57.py',
    'tests/test_step55_57_offline.py',
    'tests/test_step55_57_pg.py',
    'docs/STEP55_57_ARCHITECTURE.md',
    'docs/HUONG_DAN_BUOC_55_57.md',
)


def assess(root: Path = ROOT) -> dict:
    missing = [p for p in REQUIRED if not (root / p).is_file()]
    ci_path = root/'.github/workflows/ci.yml'
    ci = ci_path.read_text(encoding='utf-8') if ci_path.is_file() else ''
    hosted_path = root/'hosted_api/postgres.py'
    hosted = hosted_path.read_text(encoding='utf-8') if hosted_path.is_file() else ''
    adapter_path = root/'hosted_api/tenant_session_boundary.py'
    adapter = adapter_path.read_text(encoding='utf-8') if adapter_path.is_file() else ''
    checks = {
        'all_package_files_present': not missing,
        'offline_suite_registered': 'test_step55_57_offline.py -v' in ci,
        'real_pg_suite_registered': 'test_step55_57_pg.py -v' in ci,
        'prior_pg_suite_preserved': 'test_step52_54_pg.py -v' in ci,
        'ci_only_guard_present': 'self._custody._check()' in adapter,
        'legacy_shared_actor_risk_still_present': "set_config('cs.actor_id'" in hosted,
    }
    return {
        'status': 'ready_for_ci_review' if all(checks.values()) else 'incomplete',
        'checks': checks,
        'missing': missing,
        'decision': 'NO_GO',
        'public_beta_allowed': False,
        'postgres_ci_pass_derived_from_this_report': False,
        'production_oidc_path_integrated': False,
        'managed_secret_vault_integrated': False,
        'tenant_provisioning_implemented': False,
        'production_pool_or_distributed_revocation_proven': False,
        'staging_migrated': False,
        'required_next': [
            'Verify disposable PostgreSQL 17 CI Step 55-57 succeeds without skip',
            'Independently review trusted identity-to-role design and provisioning authority',
            'Choose managed vault and validate secret retrieval/rotation without exposure',
            'Implement actual hosted_api integration behind controlled feature flag',
            'Rehearse authorized staging migration, rollback, load and incident response',
        ],
    }


def main() -> int:
    result = assess()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['status'] == 'ready_for_ci_review' and not result['public_beta_allowed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
