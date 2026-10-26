"""Isolated HTTP-to-PostgreSQL vertical slice for synthetic tenant security CI.

Intentionally NOT registered in hosted_api.web, hosted_api.main or ingest.
No Uvicorn factory is exported. Requires injected CI fixture and explicit opt-in.
Do not deploy or expose to a network; environment flags are only test guardrails.
"""
from __future__ import annotations

import ipaddress
import os
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from hosted_api.tenant_session_boundary import TenantSessionBoundary
from scripts.step56_boundary_canary import IsolatedTenantBoundaryCanary

PATH = '/internal/v1/tenant/overview'


def require_disposable(boundary: TenantSessionBoundary) -> None:
    """Refuse production, staging and non-fixture providers, even with opt-in."""
    if type(boundary) is not TenantSessionBoundary:
        raise TypeError('Isolated tenant admission boundary required')
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('CYBERSENTINEL_ISOLATED_PG_CI') != '1'):
        raise RuntimeError('Experimental HTTP pilot must run in isolated CI')
    # Existing Step 41/47 guards also verify local disposable administrator DSN.
    boundary._check()
    scenario = boundary._custody._broker._scenario
    scenario._guard()
    if (not scenario.created or scenario.reverted
            or tuple(scenario.created_roles) != tuple(scenario.roles)
            or len(scenario.roles) != 2):
        raise RuntimeError('Unprovisioned or inactive disposable tenant fixture')


def create_disposable_http_pilot(boundary: TenantSessionBoundary, *, enabled: bool = False) -> FastAPI:
    """Create a separate test-only ASGI app with strict default deny.

    It is never mounted into the existing web/ingest ASGI apps. The two
    synthetic roles are selected internally by the existing verified broker.
    HTTP requests cannot specify a role, DSN, owner ID, or SQL table.
    """
    if enabled is not True:
        raise RuntimeError('Explicit test-only opt-in required')
    require_disposable(boundary)
    canary = IsolatedTenantBoundaryCanary(boundary)
    api = FastAPI(title='CyberSentinel disposable HTTP proof',
                  docs_url=None, redoc_url=None, openapi_url=None)
    api.add_middleware(TrustedHostMiddleware,
                       allowed_hosts=['localhost', '127.0.0.1', 'testserver'])

    @api.middleware('http')
    async def protect(req: Request, call_next: Any):
        host = req.client.host if req.client else ''
        try:
            local = ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = host == 'testclient'  # Starlette TestClient only
        if not local:
            return JSONResponse({'detail': 'Private test only'}, status_code=403)
        response = await call_next(req)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'"
        return response

    @api.get(PATH)
    def overview(req: Request):
        # No request-selectable user, role, database, query, or filtering.
        if req.url.query or req.headers.get('content-length') not in (None, '0'):
            return JSONResponse({'detail': 'Unsupported request'}, status_code=400)
        headers = req.headers.getlist('authorization')
        if len(headers) != 1:
            return JSONResponse({'detail': 'Authentication required'}, status_code=401)
        auth = headers[0]
        if (not isinstance(auth, str) or not auth.startswith('Bearer ')
                or len(auth) > 8200 or len(auth) < 8
                or not auth[7:] or any(c.isspace() for c in auth[7:])):
            return JSONResponse({'detail': 'Authentication required'}, status_code=401)
        try:
            require_disposable(boundary)
            counts = canary.overview(auth[7:])
            return {'mode': 'isolated_ci', 'public': False, 'table_counts': counts}
        except PermissionError:
            # Never reflect a JWT, role, domain, or DB error back to the caller.
            return JSONResponse({'detail': 'Authentication or admission denied'}, status_code=401)
        except Exception:
            # Backend outage and unexpected database exceptions fail closed.
            return JSONResponse({'detail': 'Temporary service unavailable'}, status_code=503)

    return api
