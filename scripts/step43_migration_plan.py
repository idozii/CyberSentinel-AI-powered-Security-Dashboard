"""Read-only migration decision plan. No SQL, credentials, or deployments.

This tool does not claim successful isolation of existing cs.* tables.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def assess(root: Path = ROOT) -> dict:
    old = (root / 'hosted_api/postgres.py').read_text(encoding='utf-8')
    prototype = (root / 'scripts/step41_role_boundary.py').read_text(encoding='utf-8')
    ci = (root / '.github/workflows/ci.yml').read_text(encoding='utf-8')
    findings = {
        'shared_runtime_actor_guc_still_in_use': "set_config('cs.actor_id'" in old,
        'tenant_login_poc_present': 'session_user' in prototype,
        'ci_disposable_postgres_exercise_configured': 'test_step42_43_pg.py' in ci,
        'existing_cs_tables_not_migrated': True,
        'neon_not_changed_by_this_tool': True,
        'public_ingest_not_approved': True,
    }
    return {
        'status': 'blocked_for_public_beta',
        'checks': findings,
        'phases': [
            {'id': 1, 'name': 'CI isolation', 'acceptance': 'Step41 and Step42 PG 17 jobs PASS without skip'},
            {'id': 2, 'name': 'Identity broker design', 'acceptance': 'Trusted Auth0 identity -> provisioned DB login, no caller-selected role or DSN'},
            {'id': 3, 'name': 'Least-privilege tenant lifecycle', 'acceptance': 'Provision, disable, rotate, revoke and audit credentials with secret isolation'},
            {'id': 4, 'name': 'Schema/policy migration rehearsal', 'acceptance': 'Run all cs.* RLS policy changes on a disposable restored copy; document full rollback'},
            {'id': 5, 'name': 'Application canary', 'acceptance': 'Owner portal/ingest cross-tenant, concurrency and restore testing'},
            {'id': 6, 'name': 'Security sign-off', 'acceptance': 'Independent review, deployment and incident-response evidence'},
        ],
        'rollback': 'Keep legacy staging unchanged until a reversible, verified tenant-backed cutover exists.',
        'no_go': 'Do not use this prototype against Neon or expose the portal/ingest publicly.',
    }


def main() -> int:
    print(json.dumps(assess(), indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
