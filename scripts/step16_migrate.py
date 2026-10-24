"""Explicit, checksum-checked PostgreSQL migration for private Step 16 staging.

Use migration admin credentials from CYBERSENTINEL_PG_MIGRATION_DSN (never runtime).
Do not use it against an existing production database without full backup.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

SQL_PATH = Path(__file__).resolve().parents[1] / 'hosted_api/migrations/001_initial.sql'


def run(admin_dsn: str) -> dict:
    if not admin_dsn:
        raise ValueError('Migration admin DSN missing')
    import psycopg
    from psycopg.rows import dict_row
    script = SQL_PATH.read_text(encoding='utf-8')
    digest = hashlib.sha256(script.encode('utf-8')).hexdigest()
    with psycopg.connect(admin_dsn, connect_timeout=5, row_factory=dict_row) as db:
        db.execute("SELECT pg_advisory_xact_lock(hashtext('cybersentinel-migrations'))")
        db.execute('CREATE SCHEMA IF NOT EXISTS cs')
        db.execute('''CREATE TABLE IF NOT EXISTS cs.schema_migrations(
            version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())''')
        record = db.execute('SELECT checksum FROM cs.schema_migrations WHERE version=%s', ('001',)).fetchone()
        if record:
            if record['checksum'] != digest:
                raise ValueError('Migration checksum differs - do not edit applied migration')
            return {'status': 'already-applied', 'version': '001', 'checksum': digest}
        role = db.execute("SELECT rolname FROM pg_roles WHERE rolname='cybersentinel_runtime'").fetchone()
        if not role:
            raise ValueError('Create non-superuser cybersentinel_runtime role before migration')
        # DDL is a trusted local source file, not user-supplied SQL.
        db.execute(script)
        db.execute('INSERT INTO cs.schema_migrations(version,checksum) VALUES (%s,%s)', ('001',digest))
    return {'status': 'applied', 'version': '001', 'checksum': digest}


def main() -> int:
    try:
        result = run(os.environ.get('CYBERSENTINEL_PG_MIGRATION_DSN', ''))
    except (ValueError, OSError) as exc:
        print(json.dumps({'status':'fail','detail': str(exc)},indent=2))
        return 2
    # Never print DSNs or credentials.
    print(json.dumps(result,indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
