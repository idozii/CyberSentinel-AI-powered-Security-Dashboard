"""Disposable PostgreSQL tenant credential lifecycle and privilege inspection.

CI-only proof. NEVER point this at Neon, staging, or real tenant data.
No automatic deployment, migration, or connection to any hosted service.
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

from scripts.step41_role_boundary import Fixture, protected_ci

SCHEMA_RE = re.compile(r'^cs41_[0-9a-f]{12}$')


@dataclass(frozen=True)
class DisposableTenantLifecycle:
    admin_dsn: str
    fixture: Fixture

    def __post_init__(self) -> None:
        self._guard()

    def _guard(self) -> None:
        protected_ci(self.admin_dsn)
        if not SCHEMA_RE.fullmatch(self.fixture.schema):
            raise ValueError('Refusing non-Step41 fixture schema')
        if len(self.fixture.roles) != 2 or any(
            role != f'{self.fixture.schema}_{suffix}'
            for role, suffix in zip(self.fixture.roles, ('a', 'b'))
        ):
            raise ValueError('Refusing non-Step41 fixture roles')

    def _role(self, index: int) -> str:
        self._guard()
        if index not in (0, 1):
            raise ValueError('Expected one of two disposable tenant indices')
        return self.fixture.roles[index]

    def rotate_password(self, index: int) -> str:
        """Rotate one disposable login; return the secret without printing it.

        PostgreSQL does not revoke existing authenticated sessions on rotation.
        The caller owns secure handling of this ephemeral return value.
        """
        role = self._role(index)
        from psycopg import connect, sql
        new_secret = secrets.token_urlsafe(48)
        with connect(self.admin_dsn, connect_timeout=4) as db:
            db.execute(sql.SQL('ALTER ROLE {} PASSWORD {}').format(
                sql.Identifier(role), sql.Literal(new_secret)))
        return new_secret

    def disable_login(self, index: int) -> None:
        """Prevent new logins; does not terminate already-open sessions."""
        role = self._role(index)
        from psycopg import connect, sql
        with connect(self.admin_dsn, connect_timeout=4) as db:
            db.execute(sql.SQL('ALTER ROLE {} NOLOGIN').format(sql.Identifier(role)))

    def role_state(self, index: int) -> dict:
        """Read minimal role flags; never return a password or DSN."""
        role = self._role(index)
        from psycopg import connect
        with connect(self.admin_dsn, connect_timeout=4) as db:
            record = db.execute('''
                SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreaterole,
                       rolcreatedb, rolreplication, rolinherit
                FROM pg_roles WHERE rolname = %s
            ''', (role,)).fetchone()
        if record is None:
            raise RuntimeError('Expected disposable role does not exist')
        keys = ('can_login', 'superuser', 'bypass_rls', 'create_role',
                'create_db', 'replication', 'inherits_roles')
        return dict(zip(keys, (bool(value) for value in record)))

    def privilege_state(self, index: int) -> dict:
        """Inspect minimum grants and membership in the disposable fixture."""
        role = self._role(index)
        other = self.fixture.roles[1 - index]
        schema = self.fixture.schema
        from psycopg import connect
        with connect(self.admin_dsn, connect_timeout=4) as db:
            record = db.execute('''
                SELECT has_schema_privilege(%s, %s, 'USAGE'),
                       has_schema_privilege(%s, %s, 'CREATE'),
                       has_table_privilege(%s, %s, 'SELECT'),
                       has_table_privilege(%s, %s, 'INSERT'),
                       has_table_privilege(%s, %s, 'UPDATE'),
                       pg_has_role(%s::name, %s::name, 'MEMBER')
            ''', (role, schema, role, schema,
                  role, f'{schema}.tenant_logins',
                  role, f'{schema}.tenant_events',
                  role, f'{schema}.tenant_logins',
                  role, other)).fetchone()
        keys = ('schema_usage', 'schema_create', 'mapping_select',
                'events_insert', 'mapping_update', 'member_of_other_tenant')
        return dict(zip(keys, (bool(value) for value in record)))
