"""Fail-closed, read-only audit of the *runtime credential compromise* boundary.

This is not an exploitation utility. It inspects checked-in SQL and does not
connect to PostgreSQL. Disposable PostgreSQL witness lives in CI tests.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
TABLES = ('identities', 'domains', 'agent_keys', 'telemetry_events', 'detection_alerts')


def disposable_test_dsn(dsn: str) -> bool:
    """Refuse remote or non-test DSNs before a destructive migration test."""
    try:
        url = urlsplit(dsn)
        return (url.scheme in ('postgresql', 'postgres') and
                url.hostname in ('127.0.0.1', 'localhost') and
                url.path == '/cybersentinel_stage' and not url.fragment and
                url.username is not None and url.password is not None)
    except (ValueError, TypeError):
        return False


def audit(root: Path = ROOT) -> dict:
    initial = (root / 'hosted_api/migrations/001_initial.sql').read_text(encoding='utf-8')
    monitor = (root / 'hosted_api/migrations/002_monitoring.sql').read_text(encoding='utf-8')
    runtime = (root / 'hosted_api/postgres.py').read_text(encoding='utf-8')
    sql = initial + '\n' + monitor
    checks = {
        'all_tables_rls_force': all('ALTER TABLE cs.'+table+' FORCE ROW LEVEL SECURITY' in sql for table in TABLES),
        'all_tables_use_actor_context': sql.count("current_setting('cs.actor_id'") >= 5,
        'runtime_sets_mutable_guc': "set_config('cs.actor_id', %s, true)" in runtime,
        'runtime_uses_shared_role': "role['name'] != 'cybersentinel_runtime'" in runtime,
        'no_security_definer': 'SECURITY DEFINER' not in sql.upper(),
    }
    recognized = all(checks.values())
    return {
        'status': 'pass' if recognized else 'fail',
        'audit_scope': 'source-only shared-role threat model; no database touched',
        'checks': checks,
        'finding': 'shared_runtime_role_mutable_actor_id' if recognized else 'architecture_changed_re-review_required',
        'severity': 'critical_for_public_multitenancy' if recognized else 'unknown',
        'credential_compromise_isolation_proven': False,
        'public_beta_allowed': False,
        'required_mitigation': 'Replace mutable shared-role actor context with a database-enforced identity boundary and independently test compromise resilience before exposing multitenant access.',
    }


def main() -> int:
    outcome = audit()
    print(json.dumps(outcome, indent=2, sort_keys=True))
    return 0 if outcome['status'] == 'pass' and not outcome['public_beta_allowed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
