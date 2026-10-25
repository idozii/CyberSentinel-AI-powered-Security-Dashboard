"""CI-only role-bound tenant repository; NEVER use with Neon or Internet traffic.

This adapter demonstrates authenticating through an independent PostgreSQL
LOGIN ROLE. The DB determines the tenant via session_user, never a request
parameter, JWT claim copied to SQL, or mutable cs.actor_id GUC.

Not a production provisioning service. No broker, user mapping, credential
rotation, pool management, or safe deploy cutover is implemented here.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

from scripts.step41_role_boundary import Fixture, protected_ci, tenant_dsn

if TYPE_CHECKING:
    from typing import Any


@dataclass(frozen=True)
class IsolatedTenantRepository:
    admin_dsn: str
    fixture: Fixture
    index: int

    def __post_init__(self) -> None:
        protected_ci(self.admin_dsn)
        if self.index not in (0, 1):
            raise ValueError('Only two disposable fixture tenants are supported')
        if not self.fixture.schema.startswith('cs41_'):
            raise ValueError('Expected a disposable Step 41 schema')

    def _execute(self, *, summary: str | None = None) -> list[tuple]:
        """Only reads own rows or inserts a sanitized synthetic summary.

        Role check is defense-in-depth: RLS remains the authority.
        Caller cannot specify an owner_id to impersonate another tenant.
        """
        protected_ci(self.admin_dsn)
        import psycopg
        from psycopg import sql
        role = self.fixture.roles[self.index]
        dsn = tenant_dsn(self.admin_dsn, self.fixture, self.index)
        with psycopg.connect(dsn, connect_timeout=4) as conn:
            who = conn.execute('SELECT session_user, current_user').fetchone()
            if who != (role, role):
                raise RuntimeError('Unexpected PostgreSQL login identity')
            table = sql.SQL('{}.tenant_events').format(sql.Identifier(self.fixture.schema))
            if summary is not None:
                if (not isinstance(summary, str) or not 1 <= len(summary) <= 80
                        or not summary.isascii() or not summary.isprintable()):
                    raise ValueError('Invalid synthetic event summary')
                # Owner value originates solely from fixed, CI-only fixture.
                conn.execute(sql.SQL('INSERT INTO {}(id,owner_id,summary) VALUES (%s,%s,%s)')
                             .format(table), (uuid.uuid4(), self.fixture.owners[self.index], summary))
            rows = conn.execute(sql.SQL('SELECT owner_id,summary FROM {} ORDER BY summary')
                                .format(table)).fetchall()
            if any(owner != self.fixture.owners[self.index] for owner, _ in rows):
                raise RuntimeError('Cross-tenant database row escaped RLS')
            return list(rows)

    def list_summaries(self) -> list[str]:
        return [summary for _, summary in self._execute()]

    def add_synthetic_summary(self, summary: str) -> list[str]:
        return [text for _, text in self._execute(summary=summary)]
