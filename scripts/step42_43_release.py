"""Offline release rehearsal. Never authorize a public beta."""
from __future__ import annotations

import json
from scripts.step42_43_preflight import check
from scripts.step43_migration_plan import assess
from scripts.step30_beta_gate import DEFAULT, assess as beta_assess


def rehearse() -> dict:
    pre = check()
    migration = assess()
    gate = beta_assess(json.loads(DEFAULT.read_text()))
    checks = {
        'preflight': pre['status'] == 'pass',
        'unmigrated_application_declared': migration['checks']['shared_runtime_actor_guc_still_in_use'],
        'migration_plan_not_live': migration['checks']['neon_not_changed_by_this_tool'],
        'beta_still_blocked': gate['status'] == 'blocked'
            and not gate['authorization_to_deploy_publicly'],
    }
    return {'status': 'pass' if all(checks.values()) else 'fail', 'checks': checks,
            'public_beta': 'blocked', 'staging_migrated': False,
            'required': 'Real PostgreSQL 17 CI must pass Step41 and Step42 isolated role tests.'}


def main() -> int:
    report = rehearse()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
