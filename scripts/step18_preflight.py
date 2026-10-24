"""Static fail-fast preflight. Live Postgres RLS is verified separately by CI."""
from __future__ import annotations

import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
NEEDED=(
    'hosted_api/migrations/002_monitoring.sql',
    'scripts/step18_migrate.py','hosted_api/monitoring.py',
    'hosted_api/monitoring_models.py','hosted_api/ingest.py',
    'tests/test_step18_unit.py','tests/test_step18_postgres.py',
    'tests/test_step18_web.py','docs/HUONG_DAN_BUOC_18.md',
    'docs/STEP18_MONITORING_SECURITY.md',
)


def check(root=ROOT):
    missing=[name for name in NEEDED if not (root/name).is_file()]
    if missing:
        return {'status':'fail','missing':missing}
    migration=(root/NEEDED[0]).read_text()
    ops=(root/'hosted_api/monitoring.py').read_text()
    ingest=(root/'hosted_api/ingest.py').read_text()
    portal=(root/'hosted_api/web.py').read_text()
    ci=(root/'.github/workflows/ci.yml').read_text()
    checks={
        'three_new_rls_tables': migration.count('ENABLE ROW LEVEL SECURITY') == 3 and migration.count('FORCE ROW LEVEL SECURITY') == 3,
        'tenant_fk': migration.count('FOREIGN KEY (domain_id, owner_id)')==3,
        'zero_security_definer': 'SECURITY DEFINER' not in migration,
        'hashed_agent_key': 'hashlib.sha256(token.encode()).hexdigest()' in ops,
        'transactional_ingest': 'ON CONFLICT (domain_id,agent_event_id) DO NOTHING' in ops,
        'no_public_ingest': 'local_only' in ingest and "['127.0.0.1','localhost','testserver']" in ingest,
        'browser_csrf': 'check_csrf(fields,sess)' in portal,
        'postgres_integration_ci': 'test_step18_postgres.py -v' in ci,
        'step18_static_ci': 'python -m scripts.step18_preflight' in ci,
        'legacy_sqlite_kept': (root/'owner_api/telemetry.py').is_file(),
    }
    return {'status':'pass' if all(checks.values()) else 'fail',
            'checks':checks,
            'limitations':'Static source checks; only the PostgreSQL CI job validates actual RLS and SQL migration.'}


def main():
    report=check()
    print(json.dumps(report,indent=2))
    return 0 if report['status']=='pass' else 2


if __name__=='__main__':
    raise SystemExit(main())
