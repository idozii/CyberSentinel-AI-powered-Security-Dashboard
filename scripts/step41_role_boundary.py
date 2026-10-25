"""Disposable PostgreSQL role-per-tenant isolation proof of concept.

Never migrate Neon or existing cs tables. Requires an explicit ephemeral CI guard.
A DB login role, not a caller-controlled cs.actor_id, chooses the owner scope.
"""
from __future__ import annotations

import json
import os
import secrets
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from scripts.step39_actor_boundary import disposable_test_dsn


@dataclass(frozen=True)
class Fixture:
    schema: str
    roles: tuple[str, str]
    passwords: tuple[str, str]
    owners: tuple[uuid.UUID, uuid.UUID]


def protected_ci(admin_dsn: str) -> None:
    parsed = urlsplit(admin_dsn)
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('CYBERSENTINEL_ISOLATED_PG_CI') != '1'
            or not disposable_test_dsn(admin_dsn)
            or parsed.username != 'postgres'
            or parsed.password != 'ci-ephemeral-admin'
            or parsed.port != 5432):
        raise RuntimeError('Step 41 refuses all non-disposable databases; CI-only')


def make_fixture() -> Fixture:
    nonce = uuid.uuid4().hex[:12]
    return Fixture(schema=f'cs41_{nonce}', roles=(f'cs41_{nonce}_a', f'cs41_{nonce}_b'),
                   passwords=(secrets.token_urlsafe(32), secrets.token_urlsafe(32)),
                   owners=(uuid.uuid4(), uuid.uuid4()))


def install_disposable(admin_dsn: str, fixture: Fixture) -> None:
    """Create only an isolated proof schema and two unprivileged test logins."""
    protected_ci(admin_dsn)
    import psycopg
    from psycopg import sql
    with psycopg.connect(admin_dsn, connect_timeout=4) as conn:
        for role, password in zip(fixture.roles, fixture.passwords):
            conn.execute(sql.SQL('CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER '
                                 'NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS')
                         .format(sql.Identifier(role), sql.Literal(password)))
        schema = sql.Identifier(fixture.schema)
        roles = sql.SQL(',').join(sql.Identifier(role) for role in fixture.roles)
        conn.execute(sql.SQL('CREATE SCHEMA {}').format(schema))
        conn.execute(sql.SQL('REVOKE ALL ON SCHEMA {} FROM PUBLIC').format(schema))
        conn.execute(sql.SQL('CREATE TABLE {}.tenant_logins '
                             '(login_role name PRIMARY KEY, owner_id uuid NOT NULL UNIQUE)')
                     .format(schema))
        conn.execute(sql.SQL('CREATE TABLE {}.tenant_events '
                             '(id uuid PRIMARY KEY, owner_id uuid NOT NULL, summary text NOT NULL)')
                     .format(schema))
        conn.executemany(sql.SQL('INSERT INTO {}.tenant_logins(login_role,owner_id) '
                                 'VALUES (%s,%s)').format(schema),
                         zip(fixture.roles, fixture.owners))
        conn.executemany(sql.SQL('INSERT INTO {}.tenant_events(id,owner_id,summary) '
                                 'VALUES (%s,%s,%s)').format(schema),
                         ((uuid.uuid4(), owner, f'tenant-{i}') for i, owner in enumerate(fixture.owners)))
        for table in ('tenant_logins', 'tenant_events'):
            conn.execute(sql.SQL('ALTER TABLE {}.{} ENABLE ROW LEVEL SECURITY')
                         .format(schema, sql.Identifier(table)))
            conn.execute(sql.SQL('ALTER TABLE {}.{} FORCE ROW LEVEL SECURITY')
                         .format(schema, sql.Identifier(table)))
        # tenant_logins is SELECT-only, no app role can change or provision the mapping.
        conn.execute(sql.SQL('CREATE POLICY own_login ON {}.tenant_logins '
                             'FOR SELECT TO {} USING (login_role = session_user)')
                     .format(schema, roles))
        owner_lookup = sql.SQL('(SELECT owner_id FROM {}.tenant_logins '
                               'WHERE login_role = session_user)').format(schema)
        conn.execute(sql.SQL('CREATE POLICY own_events ON {}.tenant_events '
                             'FOR ALL TO {} USING (owner_id = {}) '
                             'WITH CHECK (owner_id = {})')
                     .format(schema, roles, owner_lookup, owner_lookup))
        conn.execute(sql.SQL('GRANT USAGE ON SCHEMA {} TO {}').format(schema, roles))
        conn.execute(sql.SQL('GRANT SELECT ON {}.tenant_logins TO {}').format(schema, roles))
        conn.execute(sql.SQL('GRANT SELECT,INSERT,UPDATE,DELETE ON {}.tenant_events TO {}')
                     .format(schema, roles))
        # Never grant schema ownership, SET ROLE membership, BYPASSRLS or CREATEROLE.


def delete_disposable(admin_dsn: str, fixture: Fixture) -> None:
    """Delete the specifically named disposable fixture after test connections close."""
    protected_ci(admin_dsn)
    import psycopg
    from psycopg import sql
    with psycopg.connect(admin_dsn, connect_timeout=4) as conn:
        conn.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE')
                     .format(sql.Identifier(fixture.schema)))
        for role in fixture.roles:
            conn.execute(sql.SQL('DROP ROLE IF EXISTS {}').format(sql.Identifier(role)))


def tenant_dsn(admin_dsn: str, fixture: Fixture, which: int) -> str:
    protected_ci(admin_dsn)
    from psycopg.conninfo import make_conninfo
    return make_conninfo(admin_dsn, user=fixture.roles[which],
                         password=fixture.passwords[which], connect_timeout=4)


def assessment() -> dict:
    """Offline statement of scope; a real pass requires the dedicated PG test."""
    return {
        'status': 'design_ready',
        'prototype': 'role-per-tenant / session_user / protected mapping / forced RLS',
        'existing_shared_runtime_replaced': False,
        'neon_database_modified': False,
        'supports_public_deployment': False,
        'required_next': ['isolated PostgreSQL 17 integration CI',
                          'least-privilege provisioning and secret lifecycle',
                          'application integration and migration rehearsal',
                          'failure and cross-tenant security review'],
    }


def main() -> int:
    print(json.dumps(assessment(), indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
