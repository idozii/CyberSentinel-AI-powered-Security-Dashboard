"""Read-only five-table owner overview through CI-only tenant session boundary.

Unlike the old shared runtime, no request-supplied owner_id or mutable actor GUC
is used to choose a database identity. Not wired to FastAPI or Streamlit.
"""
from __future__ import annotations

from hosted_api.tenant_session_boundary import TenantSessionBoundary
from scripts.step47_schema_rehearsal import TABLES


class IsolatedTenantBoundaryCanary:
    def __init__(self, boundary: TenantSessionBoundary):
        if not isinstance(boundary, TenantSessionBoundary):
            raise TypeError('Expected a disposable admission boundary')
        self._boundary = boundary

    def overview(self, verified_bearer_token: str) -> dict[str, int]:
        from psycopg import sql
        with self._boundary.borrow(verified_bearer_token) as db:
            # Table names are fixed source literals; no caller-controlled SQL.
            return {table: db.execute(sql.SQL('SELECT count(*) FROM cs.{}').format(
                sql.Identifier(table))).fetchone()[0] for table in TABLES}
