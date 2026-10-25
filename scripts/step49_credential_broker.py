"""CI-only verified identity -> disposable PostgreSQL login boundary.

NOT an application authentication service or production secret vault. The
verifier and binding directory are injected by the CI harness. No connection
parameters, tenant IDs or role choices are accepted from a request.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from scripts.step41_role_boundary import protected_ci
from scripts.step46_trusted_binding import TrustedRoleBroker
from scripts.step47_schema_rehearsal import DisposableSchemaRehearsal


class DisposableCredentialBroker:
    """Prototype connection factory with in-memory disposable credentials.

    Only meaningful for the two synthetic tenants created by Step 47. There
    is no credential distribution, persistence, API exposure or pooling.
    """

    def __init__(self, scenario: DisposableSchemaRehearsal, verifier, bindings):
        scenario._guard()
        if not scenario.created or scenario.reverted or len(scenario.created_roles) != 2:
            raise RuntimeError('Step 47 isolated tenant roles must already exist')
        if tuple(scenario.created_roles) != tuple(scenario.roles):
            raise RuntimeError('Unexpected role provisioning state')
        self._scenario = scenario
        self._roles = tuple(scenario.roles)
        if len(scenario.passwords) != 2:
            raise ValueError('Expected exactly two disposable credentials')
        self._credentials = list(scenario.passwords)
        self._disabled: set[int] = set()
        authorized = tuple(bindings)
        if len(authorized) != 2 or tuple(binding[2] for binding in authorized) != self._roles:
            raise ValueError('Identity bindings must exactly match provisioned roles')
        self._resolver = TrustedRoleBroker(verifier, authorized)

    def _guard(self) -> None:
        scenario = self._scenario
        protected_ci(scenario.admin_dsn)
        scenario._guard()
        if not scenario.created or scenario.reverted or self._roles != scenario.roles:
            raise RuntimeError('Disposable tenant database no longer available')

    def _resolve(self, token: str) -> int:
        self._guard()
        try:
            bound = self._resolver.resolve(token)
        except Exception:
            # Never include token/JWT claims, DSNs or underlying verifier details.
            raise PermissionError('Authentication denied') from None
        index = bound.index
        if index in self._disabled:
            raise PermissionError('Tenant login disabled')
        if self._roles[index] != bound.login_role:
            raise PermissionError('Unexpected provisioned login role')
        return index

    @contextmanager
    def session(self, bearer_token: str) -> Iterator:
        """One transaction-free, short-lived login; always close the socket."""
        index = self._resolve(bearer_token)
        from psycopg import connect
        from psycopg.conninfo import make_conninfo

        scenario = self._scenario
        role = self._roles[index]
        # Credentials are a CI-only in-memory fixture. Never return a DSN.
        conninfo = make_conninfo(scenario.admin_dsn, dbname=scenario.name,
                                 user=role, password=self._credentials[index],
                                 connect_timeout=4)
        conn = connect(conninfo, autocommit=True, connect_timeout=4)
        try:
            who = conn.execute('SELECT session_user, current_user').fetchone()
            if who != (role, role):
                raise PermissionError('Database login identity mismatch')
            yield conn
        finally:
            conn.close()

    def _ci_operator_rotate(self, index: int) -> None:
        """Operator-only rehearsal: reject old password on NEW DB sessions.

        Existing authenticated sessions survive an ALTER ROLE PASSWORD.
        A production operator API must NOT expose this method directly.
        """
        self._guard()
        if type(index) is not int or index not in (0, 1) or index in self._disabled:
            raise ValueError('Invalid fixture tenant for rotation')
        import secrets
        from psycopg import sql
        secret = secrets.token_urlsafe(48)
        with self._scenario._admin() as db:
            db.execute(sql.SQL('ALTER ROLE {} PASSWORD {}').format(
                sql.Identifier(self._roles[index]), sql.Literal(secret)))
        # Only update in-memory synthetic credentials after admin transaction commits.
        self._credentials[index] = secret

    def _ci_operator_disable_and_terminate(self, index: int) -> int:
        """Block new login then kill existing sessions of ONE disposable role.

        This is a CI experiment. Production needs authorized operator identity,
        audit logging, pool draining, cache invalidation and incident response.
        """
        self._guard()
        if type(index) is not int or index not in (0, 1):
            raise ValueError('Invalid fixture tenant for disable')
        from psycopg import sql
        role = self._roles[index]
        # These are separate transactions: NOLOGIN must be committed before
        # terminating existing connections. Restrict termination by BOTH DB
        # name and authenticated login role, never caller-submitted values.
        with self._scenario._admin() as db:
            db.execute(sql.SQL('ALTER ROLE {} NOLOGIN').format(sql.Identifier(role)))
        self._disabled.add(index)
        with self._scenario._admin() as db:
            rows = db.execute('''SELECT pg_terminate_backend(pid) FROM pg_stat_activity
                                 WHERE datname = %s AND usename = %s
                                   AND pid <> pg_backend_pid()''',
                              (self._scenario.name, role)).fetchall()
        if any(not terminated for (terminated,) in rows):
            raise RuntimeError('Could not terminate all fixture connections')
        return len(rows)
