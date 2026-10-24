"""Verify OIDC JWT access tokens with a pinned issuer, audience and RS256 keyset.

This code verifies existing *access tokens*. It does not implement browser login,
authorization-code/PKCE, refresh tokens, signup or identity-provider provisioning.
"""
from __future__ import annotations

from dataclasses import dataclass

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWTError

from hosted_api.settings import HostedSettings


class IdentityRejected(Exception):
    pass


@dataclass(frozen=True)
class Identity:
    issuer: str
    subject: str


class OIDCVerifier:
    def __init__(self, settings: HostedSettings, jwks_client=None):
        self.settings = settings
        self.jwks = jwks_client or PyJWKClient(settings.jwks_url, cache_jwk_set=True, lifespan=300, timeout=3)

    def verify(self, token: str) -> Identity:
        if not isinstance(token, str) or not 50 <= len(token) <= 8192:
            raise IdentityRejected('Invalid bearer token')
        try:
            header = jwt.get_unverified_header(token)
            if (header.get('alg') != 'RS256' or not isinstance(header.get('kid'), str)
                    or not 1 <= len(header['kid']) <= 256
                    or any(field in header for field in ('jku', 'x5u', 'crit'))):
                raise IdentityRejected('Unsupported token header')
            key = self.jwks.get_signing_key_from_jwt(token)
            if getattr(key, 'algorithm_name', 'RS256') != 'RS256':
                raise IdentityRejected('Unsupported signing key')
            claims = jwt.decode(
                token, key.key, algorithms=['RS256'],
                audience=self.settings.audience, issuer=self.settings.issuer,
                options={'require': ['iss', 'aud', 'sub', 'exp', 'iat'], 'verify_iat': True},
                leeway=30,
            )
        except IdentityRejected:
            raise
        except (PyJWTError, ValueError, TypeError, OSError) as exc:
            raise IdentityRejected('Token verification failed') from exc
        subject = claims.get('sub')
        if not isinstance(subject, str) or not 1 <= len(subject) <= 255:
            raise IdentityRejected('Invalid subject')
        return Identity(issuer=self.settings.issuer, subject=subject)
