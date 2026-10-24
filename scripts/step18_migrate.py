"""Checksum-checked, transaction-atomic migration 002 for private monitoring.

Require CYBERSENTINEL_PG_MIGRATION_DSN with migration-owner credentials.
Do not apply until Step 17 is committed, tested, and backed up.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

SQL_PATH = Path(__file__).resolve().parents[1] / 'hosted_api/migrations/002_monitoring.sql'


def run(admin_dsn: str) -> dict:
    if not admin_dsn:
        raise ValueError('Migration admin DSN missing')
    import psycopg
    from psycopg.rows import dict_row
    content = SQL_PATH.read_text(encoding='utf-8')
    checksum = hashlib.sha256(content.encode('utf-8')).hexdigest()
    with psycopg.connect(admin_dsn, connect_timeout=5, row_factory=dict_row) as conn:
        conn.execute("SELECT pg_advisory_xact_lock(hashtext('cybersentinel-migrations'))")
        previous = conn.execute("SELECT version FROM cs.schema_migrations WHERE version='001'").fetchone()
        if not previous:
            raise ValueError('Apply migration 001 first')
        applied = conn.execute("SELECT checksum FROM cs.schema_migrations WHERE version='002'").fetchone()
        if applied:
            if applied['checksum'] != checksum:
                raise ValueError('Migration 002 checksum mismatch - do not edit applied SQL')
            return {'status': 'already-applied', 'version': '002', 'checksum': checksum}
        role = conn.execute("SELECT current_user AS name").fetchone()
        if role is None or role['name'] == 'cybersentinel_runtime':
            raise ValueError('Migration requires a non-runtime administrative role')
        conn.execute(content)
        conn.execute("INSERT INTO cs.schema_migrations(version,checksum) VALUES('002',%s)", (checksum,))
    return {'status':'applied','version':'002','checksum':checksum}


def main() -> int:
    try:
        print(json.dumps(run(os.environ.get('CYBERSENTINEL_PG_MIGRATION_DSN', '')), indent=2))
        return 0
    except (ValueError, OSError) as exc:
        print(json.dumps({'status':'fail', 'detail':str(exc)},indent=2))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
