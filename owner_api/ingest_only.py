"""Strictly limited staging ingest ASGI app - no owner routes, no Swagger docs.

Run on loopback: uvicorn owner_api.ingest_only:app --host 127.0.0.1 --port 8004
Place behind an exact-path HTTPS reverse proxy. Never expose port 8004.
"""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path

from fastapi import FastAPI, Request, Security, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.trustedhost import TrustedHostMiddleware

from owner_api.main import TelemetryBatch, DEFAULT_DB
from owner_api.store import OwnerError, OwnerStore
from owner_api.telemetry import TelemetryStore

bearer = HTTPBearer(auto_error=False)


def create_ingest_app(db_path: Path | None = None) -> FastAPI:
    owner = OwnerStore(db_path or Path(os.environ.get('CYBERSENTINEL_OWNER_DB', DEFAULT_DB)))
    telemetry = TelemetryStore(owner)
    api = FastAPI(title='CyberSentinel Staging Ingest', version='0.1.0',
                  docs_url=None, redoc_url=None, openapi_url=None)
    api.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1', 'localhost', 'testserver'])

    @api.middleware('http')
    async def local_only_and_size(request: Request, call_next):
        host = request.client.host if request.client else ''
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == 'testclient'
        if not loopback:
            return JSONResponse(status_code=403, content={'detail':'Loopback upstream only'})
        if request.url.path == '/agent/v1/ingest':
            length = request.headers.get('content-length', '')
            if not length.isdecimal():
                return JSONResponse(status_code=411, content={'detail':'Content-Length required'})
            if int(length) > 32768:
                return JSONResponse(status_code=413, content={'detail':'Body too large'})
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    @api.exception_handler(OwnerError)
    async def owner_error(_request, exc: OwnerError):
        return JSONResponse(status_code=exc.status, content={'detail':str(exc)})

    @api.post('/agent/v1/ingest')
    def ingest(payload: TelemetryBatch,
               credentials: HTTPAuthorizationCredentials | None = Security(bearer)):
        if credentials is None or credentials.scheme.lower() != 'bearer':
            raise HTTPException(401, detail='Agent authentication required')
        return telemetry.ingest(credentials.credentials, payload.domain_id,
                                [ev.model_dump() for ev in payload.events])

    return api


app = create_ingest_app()
