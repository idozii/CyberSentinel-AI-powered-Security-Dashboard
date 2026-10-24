"""Single offline release rehearsal for Steps 26-30; never deploys the service."""
from __future__ import annotations

import json

from scripts.step25_release import release_smoke
from scripts.step26_30_preflight import check
from scripts.step27_tenant_audit import offline_audit
from scripts.step29_reliability_drill import reliability_drill
from scripts.step30_beta_gate import DEFAULT, assess


def rehearse() -> dict:
    smoke = release_smoke()
    preflight = check()
    rls = offline_audit()
    reliability = reliability_drill()
    evidence = json.loads(DEFAULT.read_text())
    gate = assess(evidence)
    checks = {
        'existing_local_mvp': smoke['status'] == 'pass',
        'packaging_preflight': preflight['status'] == 'pass',
        'rls_migration_inspection': rls['status'] == 'pass',
        'synthetic_fault_drill': reliability['status'] == 'pass',
        'public_beta_fail_closed': gate['status'] == 'blocked' and not gate['authorization_to_deploy_publicly'],
    }
    return {'status': 'pass' if all(checks.values()) else 'fail',
            'checks': checks, 'local_release_scope': 'private, ephemeral, synthetic, localhost only',
            'beta_gate': gate['status'], 'beta_conditions_outstanding': len(gate['missing_conditions']),
            'warning': 'PASS means offline release rehearsal, NOT a production or limited beta launch.'}


def main() -> int:
    report = rehearse()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
