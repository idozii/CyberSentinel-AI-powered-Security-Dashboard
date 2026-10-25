"""Fail-closed offline assessment. PASS = assessment, NOT deployment approval."""
from __future__ import annotations

import json

from scripts.step36_38_release import rehearse as previous_rehearsal
from scripts.step39_actor_boundary import audit
from scripts.step39_40_preflight import check
from scripts.step40_readiness_report import readiness


def rehearse() -> dict:
    earlier = previous_rehearsal()
    static = check()
    actor = audit()
    gate = readiness()
    checks = {
        'step36_38_release': earlier['status'] == 'pass',
        'step39_40_preflight': static['status'] == 'pass',
        'actor_risk_recognized': actor['status'] == 'pass' and actor['finding'] == 'shared_runtime_role_mutable_actor_id',
        'staging_credentials_still_untrusted': not actor['credential_compromise_isolation_proven'],
        'external_beta_gate_blocked': gate['status'] == 'blocked' and not gate['public_beta_allowed'],
        'disposable_postgres_witness_in_ci': static['checks']['ci_disposable_witness'],
    }
    return {'status': 'pass' if all(checks.values()) else 'fail', 'checks': checks,
            'scope': 'Security audit tooling only; no live backup, DNS or TLS tested',
            'beta_gate': 'blocked', 'authorization_to_deploy_publicly': False}


def main() -> int:
    outcome = rehearse()
    print(json.dumps(outcome, indent=2, sort_keys=True))
    return 0 if outcome['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
