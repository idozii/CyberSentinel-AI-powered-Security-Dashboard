"""CI-only broker design: verified OIDC identity to allowlisted tenant role.

The verifier is injected and MUST be a production-configured OIDCVerifier in a
future application integration. This prototype neither distributes DB secrets
nor authorizes application integration. Do not use a fake verifier in services.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from hosted_api.identity import Identity

ROLE_RE = re.compile(r'^cs46_[a-f0-9]{12}_[ab]$')


class OIDCVerifierProtocol(Protocol):
    def verify(self, token: str) -> 'Identity': ...


@dataclass(frozen=True)
class BoundTenant:
    index: int
    login_role: str


class TrustedRoleBroker:
    """Explicitly provisioned identity mapping, with no user-supplied role.

    This is only a narrow resolver design. The caller's injected verifier and
    the provisioning channel remain security-critical and are not proven here.
    """

    def __init__(self, verifier: OIDCVerifierProtocol, bindings: tuple[tuple[str, str, str], ...]):
        self._verifier = verifier
        directory: dict[tuple[str, str], BoundTenant] = {}
        used_roles: set[str] = set()
        expected_prefix: str | None = None
        for index, (issuer, subject, role) in enumerate(bindings):
            if (not isinstance(issuer, str) or not issuer.startswith('https://')
                    or not isinstance(subject, str) or not subject
                    or not isinstance(role, str) or not ROLE_RE.fullmatch(role)
                    or (issuer, subject) in directory or role in used_roles
                    or index > 1):
                raise ValueError('Invalid or duplicate provisioned binding')
            prefix, suffix = role.rsplit('_', 1)
            if suffix != ('a', 'b')[index] or (expected_prefix is not None and prefix != expected_prefix):
                raise ValueError('Provisioned roles must be a single paired fixture')
            expected_prefix = prefix
            directory[(issuer, subject)] = BoundTenant(index=index, login_role=role)
            used_roles.add(role)
        if len(directory) != 2:
            raise ValueError('The isolated proof requires exactly two bindings')
        self._directory = directory

    def resolve(self, bearer_token: str) -> BoundTenant:
        """Always verify bearer through injected verifier before role selection."""
        if not isinstance(bearer_token, str) or not 1 <= len(bearer_token) <= 8192:
            raise PermissionError('Invalid bearer token')
        try:
            identity = self._verifier.verify(bearer_token)
            issuer = identity.issuer
            subject = identity.subject
            if not isinstance(issuer, str) or not isinstance(subject, str):
                raise PermissionError('Invalid verified identity')
            return self._directory[(issuer, subject)]
        except (KeyError, AttributeError, TypeError, ValueError) as exc:
            raise PermissionError('Unprovisioned or invalid identity') from exc
