"""Read-only RLS/role inspection for private PostgreSQL staging.

No tenant data is returned, no migrations are applied and no roles are changed.
The optional live audit uses the runtime account only, not the owner account.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TABLES = ('identities', 'domains', 'agent_keys', 'telemetry_events', 'detection_alerts')


def offline_audit(root: Path = ROOT) -> dict:
    a = (root / 'hosted_api/migrations/001_identity.sql')
    if not a.exists():
        # Support historical file naming if it changes in a later release.
        a = root / 'hosted_api/migrations/001_initial.sql'
    migration_files = list((root / 'hosted_api/migrations').glob('001*.sql')) + list(
        (root / 'hosted_api/migrations').glob('002*.sql'))
    merged = '\n'.join(p.read_text(encoding='utf-8') for p in migration_files)
    checked = {}
    for table in TABLES:
        checked[table] = bool(re.search(r'ALTER\s+TABLE\s+cs\.' + table +
                         r'\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY\s*;', merged, re.I)) and bool(
                         re.search(r'ALTER\s+TABLE\s+cs\.' + table +
                         r'\s+FORCE\s+ROW\s+LEVEL\s+SECURITY\s*;', merged, re.I))
    checked['no_security_definer_in_migrations'] = 'SECURITY DEFINER' not in merged.upper()
    checked['runtime_must_not_be_owner'] = 'cybersentinel_runtime' in merged
    checked['five_expected_tables'] = len(TABLES) == 5 and len(migration_files) == 2
    return {'status': 'pass' if all(checked.values()) else 'fail',
            'checks': checked, 'mode': 'offline-source-only',
            'limits': 'Static checks do not prove RLS behaviour. CI runs real Postgres integration tests.'}


def live_runtime_audit(dsn: str) -> dict:
    """Query database metadata using only the least-privilege role."""
    import psycopg
    results: dict[str, bool] = {}
    with psycopg.connect(dsn, connect_timeout=10) as db:
        role = db.execute('''SELECT current_user, current_database(), r.rolsuper, r.rolbypassrls
          FROM pg_roles r WHERE r.rolname = current_user''').fetchone()
        if not role:
            raise ValueError('Could not determine database role')
        results['least_privilege_role'] = role[0] == 'cybersentinel_runtime' and not role[2] and not role[3]
        results['expected_database'] = role[1] == 'cybersentinel_stage'
        rows = db.execute('''SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
                 pg_get_userbyid(c.relowner) AS owner
            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'cs' AND c.relname = ANY(%s)''', (list(TABLES),)).fetchall()
        by_name = {r[0]: r for r in rows}
        for table in TABLES:
            row = by_name.get(table)
            results['rls_' + table] = bool(row and row[1] and row[2] and row[3] != 'cybersentinel_runtime')
        # An arbitrary unknown actor must have no access to other owners' rows.
        # This does not prove cross-owner isolation on its own; CI tests cover it.
        db.execute("SELECT set_config('cs.actor_id', %s, true)", (str(uuid.uuid4()),))
        for table in TABLES:
            try:
                n = db.execute('SELECT count(*) FROM cs.' + table).fetchone()[0]
                results['empty_actor_' + table] = n == 0
            except psycopg.Error:
                # A permission denial also fails closed.
                db.rollback()
                results['empty_actor_' + table] = False
                break
        db.rollback()
    return {'status': 'pass' if all(results.values()) else 'fail',
            'checks': results, 'mode': 'read-only-runtime-database',
            'limits': 'This audit does not replace adversarial two-tenant CI tests or an independent security review.'}


def main() -> int:
    parser = argparse.ArgumentParser(description='Offline and optional read-only private RLS audit')
    parser.add_argument('--live', action='store_true', help='Inspect actual staging via CYBERSENTINEL_PG_RUNTIME_DSN')
    args = parser.parse_args()
    result = offline_audit()
    if args.live:
        dsn = os.environ.get('CYBERSENTINEL_PG_RUNTIME_DSN', '')
        if not dsn:
            parser.error('CYBERSENTINEL_PG_RUNTIME_DSN not set; never pass it as CLI text')
        try:
            live = live_runtime_audit(dsn)
            result = {'offline': result, 'live': live,
                      'status': 'pass' if result['status'] == live['status'] == 'pass' else 'fail'}
        except Exception as exc:
            # Do not echo driver exceptions; these can include host/user details.
            result = {'status': 'fail', 'error_type': type(exc).__name__,
                      'detail': 'Database audit failed. Inspect local confidential logs.'}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
