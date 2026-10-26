"""Honest fail-closed inventory for Steps 58-63; NO-GO for deployment."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    'hosted_api/disposable_tenant_http.py',
    'scripts/install_step58_63.py',
    'scripts/step63_security_gate.py',
    'tests/test_step58_63_offline.py',
    'tests/test_step58_63_pg.py',
    'docs/STEP58_63_ARCHITECTURE.md',
    'docs/HUONG_DAN_BUOC_58_63.md',
)


def assess(root: Path = ROOT) -> dict:
    missing = [name for name in REQUIRED if not (root/name).is_file()]
    workflow = root/'.github/workflows/ci.yml'
    ci = workflow.read_text(encoding='utf-8') if workflow.is_file() else ''
    legacy = root/'hosted_api/postgres.py'
    old = legacy.read_text(encoding='utf-8') if legacy.is_file() else ''
    api_path = root/'hosted_api/disposable_tenant_http.py'
    api = api_path.read_text(encoding='utf-8') if api_path.is_file() else ''
    checks = {
        'files_present': not missing,
        'offline_tests_registered': 'test_step58_63_offline.py -v' in ci,
        'real_postgres_tests_registered': 'test_step58_63_pg.py -v' in ci,
        'previous_pg_proof_preserved': 'test_step55_57_pg.py -v' in ci,
        'explicit_ci_guard': "os.environ.get('CYBERSENTINEL_ISOLATED_PG_CI')" in api,
        'legacy_shared_runtime_threat_still_present': "set_config('cs.actor_id'" in old,
        'existing_service_unchanged': all(
            (root/name).is_file() and 'disposable_tenant_http' not in
            (root/name).read_text(encoding='utf-8')
            for name in ('hosted_api/web.py', 'hosted_api/ingest.py')), 
    }
    return {
        'status': 'ready_for_ci_review' if all(checks.values()) else 'incomplete',
        'missing': missing,
        'checks': checks,
        'proof_scope': 'HTTP to RS256 OIDC to disposable PostgreSQL role-bound RLS',
        'real_pg_ci_result': 'not_determined_by_static_gate',
        'legacy_hosted_api_migrated': False,
        'managed_vault_integrated': False,
        'production_identity_broker_integrated': False,
        'real_tenant_provisioning': False,
        'authorized_staging_cutover': False,
        'independent_security_review': False,
        'public_beta_allowed': False,
        'decision': 'NO_GO',
        'next': 'Implement reviewed provisioning and vault integration and perform authorized private staging canary before considering limited beta.',
    }


def main() -> int:
    result = assess()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['status'] == 'ready_for_ci_review' and not result['public_beta_allowed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
