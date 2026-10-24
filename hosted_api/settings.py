"""Fail-closed environment configuration for a private hosted-identity staging API."""
from __future__ import annotations

import os
import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class HostedSettings:
    issuer: str
    audience: str
    jwks_url: str
    runtime_dsn: str

    @staticmethod
    def validate(issuer: str, audience: str, jwks_url: str, runtime_dsn: str) -> 'HostedSettings':
        if not issuer or len(issuer) > 512 or not audience or len(audience) > 256 or not runtime_dsn:
            raise ValueError('OIDC issuer, audience and database DSN must be configured')
        for name, value in (('issuer', issuer), ('JWKS URL', jwks_url)):
            p = urlsplit(value)
            try:
                port = p.port
            except ValueError as exc:
                raise ValueError(name + ' has an invalid port') from exc
            host = (p.hostname or '').lower().rstrip('.')
            if (p.scheme != 'https' or not host or p.username or p.password
                    or port not in (None, 443) or p.fragment or p.query
                    or host == 'localhost' or host.endswith(('.localhost', '.local', '.internal'))):
                raise ValueError(name + ' must be an administrator-pinned public HTTPS URL')
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                if not address.is_global:
                    raise ValueError(name + ' cannot use a non-public IP')
        if not jwks_url or len(jwks_url) > 512:
            raise ValueError('JWKS URL is required')
        if issuer.endswith('/') and not urlsplit(issuer).path:
            # Exact OIDC issuer comparison uses the configured value verbatim.
            pass
        return HostedSettings(issuer, audience, jwks_url, runtime_dsn)

    @classmethod
    def from_env(cls) -> 'HostedSettings':
        return cls.validate(
            os.environ.get('CYBERSENTINEL_OIDC_ISSUER', ''),
            os.environ.get('CYBERSENTINEL_OIDC_AUDIENCE', ''),
            os.environ.get('CYBERSENTINEL_OIDC_JWKS_URL', ''),
            os.environ.get('CYBERSENTINEL_PG_RUNTIME_DSN', ''),
        )
