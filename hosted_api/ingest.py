"""Private localhost-only Postgres ingest app - separate from Auth0 owner BFF.

Run on 127.0.0.1:8008 ONLY. No Caddy forwarding in Step 18.
"""
from __future__ import annotations

import ipaddress
import os
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi import Security
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from hosted_api.monitoring import MonitoringStore
from hosted_api.postgres import HostedError
from hosted_api.monitoring_models import TelemetryEvent

bearer = HTTPBearer(auto_error=False)


class HostedBatch(BaseModel):
    model_config = ConfigDict(extra='forbid')
    domain_id: uuid.UUID
    events: list[TelemetryEvent] = Field(min_length=1, max_length=25)


def create_ingest_app(store: MonitoringStore | None = None) -> FastAPI:
    # The role and the live database are validated on connection in _set_actor.
    pg = store or MonitoringStore(os.environ['CYBERSENTINEL_PG_RUNTIME_DSN'])
    api = FastAPI(title='CyberSentinel Private PostgreSQL Ingest',
                  docs_url=None, redoc_url=None, openapi_url=None)
    api.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1','localhost','testserver'])

    @api.middleware('http')
    async def local_only(request: Request, call_next):
        client = request.client.host if request.client else ''
        try:
            allowed = ipaddress.ip_address(client).is_loopback
        except ValueError:
            allowed = client == 'testclient'
        if not allowed:
            return JSONResponse(status_code=403,content={'detail':'Private localhost ingestion only'})
        if request.url.path == '/agent/v1/ingest':
            length = request.headers.get('content-length','')
            if not length.isdecimal():
                return JSONResponse(status_code=411,content={'detail':'Content-Length required'})
            if int(length) > 32768:
                return JSONResponse(status_code=413,content={'detail':'Body too large'})
        response = await call_next(request)
        response.headers['Cache-Control']='no-store'
        response.headers['X-Content-Type-Options']='nosniff'
        return response

    @api.exception_handler(HostedError)
    async def hosted_error(_request: Request, exc: HostedError):
        # Never reveal storage stack traces or tenant details to unauthenticated agents.
        return JSONResponse(status_code=exc.code if exc.code < 500 else 503,
                            content={'detail':str(exc) if exc.code < 500 else 'Storage unavailable'})

    @api.post('/agent/v1/ingest')
    def ingest(payload: HostedBatch, credentials: HTTPAuthorizationCredentials | None = Security(bearer)):
        if credentials is None or credentials.scheme.lower() != 'bearer':
            raise HTTPException(401, detail='Agent credentials required')
        return pg.ingest(credentials.credentials,payload.domain_id,
                         [ev.model_dump() for ev in payload.events])

    @api.get('/health')
    def health():
        return {'status':'ok','mode':'private-postgres-telemetry-pilot','public':False}

    return api


def factory() -> FastAPI:
    return create_ingest_app()
