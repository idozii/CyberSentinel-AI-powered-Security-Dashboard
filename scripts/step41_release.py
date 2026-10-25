"""Non-deploying Step 41 verification; public release must remain blocked."""
from __future__ import annotations

import json
from scripts.step39_actor_boundary import audit
from scripts.step30_beta_gate import DEFAULT, assess
from scripts.step41_role_boundary import assessment
from scripts.step41_preflight import check


def rehearse() -> dict:
    pre = check()
    old = audit()
    new = assessment()
    gate = assess(json.loads(DEFAULT.read_text()))
    checks = {
        'installed_preflight': pre['status'] == 'pass',
        'legacy_exposure_still_detected': old['status'] == 'pass'
            and not old['credential_compromise_isolation_proven'],
        'prototype_does_not_change_neon': not new['neon_database_modified'],
        'existing_shared_runtime_not_replaced': not new['existing_shared_runtime_replaced'],
        'public_beta_blocked': gate['status'] == 'blocked'
            and not gate['authorization_to_deploy_publicly'],
    }
    return {'status': 'pass' if all(checks.values()) else 'fail',
            'checks': checks, 'public_beta': 'blocked',
            'limitations': 'Real role isolation is checked ONLY by PostgreSQL 17 CI tests. '
                           'Step 41 proof does not yet protect existing cs application tables.'}


def main() -> int:
    result = rehearse()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
