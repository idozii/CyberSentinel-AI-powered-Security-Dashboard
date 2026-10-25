"""CI-only tenant session admission boundary for the disposable PostgreSQL PoC.

No FastAPI routes, live DSN, Auth0 deployment or managed vault integration.
This adapter wraps Step 52's guarded custody facade and NEVER routes a request
through the legacy shared-runtime cs.actor_id connection.
"""
from __future__ import annotations

from contextlib import contextmanager
from threading import RLock
from typing import Iterator

from scripts.step52_credential_custody import DisposableCredentialCustody


class TenantSessionBoundary:
    """Bound concurrent sessions per synthetic tenant; fail closed on disable.

    Only Step 47's two disposable fixture identities/roles are supported.
    This class is not an authorization API or a production pool/vault.
    """

    def __init__(self, custody: DisposableCredentialCustody, *, max_per_tenant: int = 2):
        if not isinstance(custody, DisposableCredentialCustody):
            raise TypeError('Requires disposable credential custody')
        custody._check()
        if type(max_per_tenant) is not int or not 1 <= max_per_tenant <= 16:
            raise ValueError('Invalid fixture session limit')
        self._custody = custody
        self._lock = RLock()
        self._inflight = [0, 0]
        self._blocked: set[int] = set()
        self._closed = False
        self._limit = max_per_tenant
        self._denied = 0
        self._admitted = 0
        self._operator_disables = 0

    def _check(self) -> None:
        # This is the CI-only guard: it refuses Neon or any non-disposable DB.
        self._custody._check()
        if self._closed:
            raise RuntimeError('Tenant session admission is closed')

    @contextmanager
    def borrow(self, bearer_token: str) -> Iterator:
        """Resolve the VERIFIED token, enforce a cap, yield only its DB role.

        The bearer may not provide an owner UUID, database role, or DSN.
        Exceptions always release the admission slot.
        """
        with self._lock:
            self._check()
            try:
                index = self._custody._broker._resolve(bearer_token)
            except Exception:
                self._denied += 1
                raise PermissionError('Authentication denied') from None
            if type(index) is not int or index not in (0, 1):
                self._denied += 1
                raise PermissionError('Unexpected provisioned tenant')
            if index in self._blocked:
                self._denied += 1
                raise PermissionError('Tenant disabled')
            if self._inflight[index] >= self._limit:
                self._denied += 1
                raise PermissionError('Tenant session capacity exceeded')
            self._inflight[index] += 1
        try:
            with self._custody.session(bearer_token) as conn:
                who = conn.execute('SELECT session_user, current_user').fetchone()
                expected = self._custody._broker._scenario.roles[index]
                if who != (expected, expected):
                    raise PermissionError('Unexpected database login identity')
                with self._lock:
                    self._admitted += 1
                yield conn
        finally:
            with self._lock:
                self._inflight[index] -= 1

    def _ci_operator_disable(self, index: int) -> int:
        """Block admission first, then disable+terminate one CI fixture role.

        If the DB operation fails, this boundary stays blocked (fail closed).
        It does not claim to provide production-wide distributed revocation.
        """
        if type(index) is not int or index not in (0, 1):
            raise ValueError('Invalid disposable fixture index')
        with self._lock:
            self._check()
            self._blocked.add(index)
            self._operator_disables += 1
        return self._custody._ci_operator_disable(index)

    def seal(self) -> None:
        """Stop future access; existing sessions must drain/terminate separately."""
        with self._lock:
            self._check()
            self._closed = True
            self._custody.seal()

    def report(self) -> dict:
        """Never disclose passwords, bearer tokens, roles, DSNs or subjects."""
        with self._lock:
            return {
                'scope': 'disposable_ci_only',
                'new_access_closed': self._closed,
                'active_fixture_sessions': sum(self._inflight),
                'blocked_fixture_logins': len(self._blocked),
                'admitted_sessions': self._admitted,
                'denied_requests': self._denied,
                'operator_disables': self._operator_disables,
                'max_per_fixture_tenant': self._limit,
                'production_connection_pool': False,
                'managed_secret_vault': False,
                'independent_security_review': False,
            }
