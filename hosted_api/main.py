"""OIDC + Postgres owner staging - loopback only, not a public signup service.

Start only after applying migration as a separate admin role:
uvicorn hosted_api.main:create_app --factory --host 127.0.0.1 --port 8006
"""
from __future__ import annotations

import ipaddress
import uuid

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from hosted_api.identity import IdentityRejected, OIDCVerifier
from hosted_api.postgres import HostedError, HostedStore
from hosted_api.settings import HostedSettings
from owner_api.dns_verify import lookup_txt

bearer = HTTPBearer(auto_error=False)


class DomainInput(BaseModel):
    domain: str = Field(min_length=3, max_length=253)


def create_app(settings: HostedSettings | None = None, verifier=None, store=None, dns_lookup=None) -> FastAPI:
    cfg = settings or HostedSettings.from_env()
    verify = verifier or OIDCVerifier(cfg)
    pg = store or HostedStore(cfg.runtime_dsn)
    dns = dns_lookup or lookup_txt
    api = FastAPI(title='CyberSentinel Hosted Identity Staging', version='0.1.0',
                  description='Loopback-only OIDC/PostgreSQL pilot - not a public owner service',
                  docs_url=None, redoc_url=None, openapi_url=None)
    api.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1','localhost','testserver'])

    @api.middleware('http')
    async def local_only(request: Request, call_next):
        host = request.client.host if request.client else ''
        try:
            good = ipaddress.ip_address(host).is_loopback
        except ValueError:
            good = host == 'testclient'
        if not good:
            return JSONResponse({'detail': 'Private staging only'}, status_code=403)
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    @api.exception_handler(HostedError)
    async def handle_hosted(_req: Request, err: HostedError):
        return JSONResponse({'detail': str(err)}, status_code=err.code)

    def current(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
        if credentials is None or credentials.scheme.lower() != 'bearer':
            raise HTTPException(401, detail='OIDC access token required')
        try:
            subject = verify.verify(credentials.credentials)
        except IdentityRejected:
            raise HTTPException(401, detail='Invalid OIDC access token') from None
        pg.ensure_identity(subject)
        return subject

    @api.get('/hosted/v1/health')
    def health():
        return {'status': 'ok', 'mode': 'private-postgres-oidc-pilot', 'public_signup': False,
                'live_telemetry_migrated': False}

    @api.get('/hosted/v1/me')
    def me(subject=Depends(current)):
        from hosted_api.postgres import identity_id
        return {'id': str(identity_id(subject)), 'issuer': subject.issuer,
                'email_collected': False}

    @api.get('/hosted/v1/domains')
    def domains(subject=Depends(current)):
        return {'domains': pg.list_domains(subject)}

    @api.post('/hosted/v1/domains', status_code=201)
    def add_domain(body: DomainInput, subject=Depends(current)):
        return pg.create_domain(subject, body.domain)

    @api.post('/hosted/v1/domains/{domain_id}/verify')
    def confirm(domain_id: uuid.UUID, subject=Depends(current)):
        return pg.verify_domain(subject, domain_id, dns)

    return api
