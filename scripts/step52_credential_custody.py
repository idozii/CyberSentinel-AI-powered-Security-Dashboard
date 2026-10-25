"""Step 52: CI-only credential custody facade for synthetic tenant logins.

Secrets stay inside Step 49's in-memory broker. This is not a secrets vault,
identity provider or general provisioning API. Requires Step 47 disposable DB.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from scripts.step49_credential_broker import DisposableCredentialBroker


@dataclass(frozen=True)
class AuditRecord:
    sequence: int
    action: str
    fixture_index: int | None


class DisposableCredentialCustody:
    """Expose only short-lived, role-bound sessions; never export raw secrets."""

    def __init__(self, broker: DisposableCredentialBroker):
        if not isinstance(broker, DisposableCredentialBroker):
            raise TypeError('Expected the Step 49 disposable broker')
        broker._guard()
        self._broker = broker
        self._enabled = True
        self._sequence = 0
        self._audit: list[AuditRecord] = []
        self._rotation_count = 0
        self._disabled_count = 0

    def _record(self, action: str, index: int | None = None) -> None:
        # No token, password, connection string, subject or external tenant ID.
        self._sequence += 1
        self._audit.append(AuditRecord(self._sequence, action, index))
        if len(self._audit) > 128:
            self._audit.pop(0)

    def _check(self) -> None:
        self._broker._guard()
        if not self._enabled:
            raise RuntimeError('Disposable credential custody is closed')

    @contextmanager
    def session(self, bearer_token: str) -> Iterator:
        self._check()
        try:
            with self._broker.session(bearer_token) as db:
                # Only session-bound connections leave the underlying broker.
                self._record('session_open')
                yield db
        except PermissionError:
            self._record('authentication_denied')
            raise

    def _ci_operator_rotate(self, index: int) -> None:
        """Rehearse password rotation via the existing, guarded broker."""
        self._check()
        if type(index) is not int or index not in (0, 1):
            raise ValueError('Invalid fixture index')
        self._broker._ci_operator_rotate(index)
        self._rotation_count += 1
        self._record('credential_rotated', index)

    def _ci_operator_disable(self, index: int) -> int:
        """Rehearse NOLOGIN plus termination of pre-existing fixture sessions."""
        self._check()
        if type(index) is not int or index not in (0, 1):
            raise ValueError('Invalid fixture index')
        count = self._broker._ci_operator_disable_and_terminate(index)
        self._disabled_count += 1
        self._record('tenant_disabled', index)
        return count

    def seal(self) -> None:
        """Block new sessions through this facade (not a DB revocation)."""
        self._check()
        self._record('custody_sealed')
        self._enabled = False

    def report(self) -> dict:
        """Redacted fixture audit only, with no security-sensitive identifiers."""
        return {
            'scope': 'disposable_ci_only',
            'enabled': self._enabled,
            'rotations': self._rotation_count,
            'disabled_fixture_logins': self._disabled_count,
            'records': [r.__dict__.copy() for r in self._audit],
            'managed_vault_integrated': False,
            'external_provisioning_enabled': False,
        }
