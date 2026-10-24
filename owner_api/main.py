"""LOCAL DEVELOPMENT ONLY: CyberSentinel owner onboarding API.

Run: uvicorn owner_api.main:app --host 127.0.0.1 --port 8002
Never expose this prototype directly to the internet.
"""
from __future__ import annotations

import ipaddress
import os
import time
from pathlib import Path
from typing import Callable

from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, SecretStr
from starlette.middleware.trustedhost import TrustedHostMiddleware

from owner_api.dns_verify import LookupUnavailable, lookup_txt
from owner_api.store import OwnerError, OwnerStore

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "simulations/runtime/owner/owner_local.sqlite3"
bearer = HTTPBearer(auto_error=False)


class Registration(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: SecretStr


class Login(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: SecretStr


class AddDomain(BaseModel):
    domain: str = Field(min_length=3, max_length=253)


def create_app(db_path: Path | None = None, txt_lookup: Callable[[str], list[str]] | None = None) -> FastAPI:
    store = OwnerStore(db_path or Path(os.environ.get("CYBERSENTINEL_OWNER_DB", DEFAULT_DB)))
    lookup = txt_lookup or lookup_txt
    api = FastAPI(title="CyberSentinel Owner Onboarding — Local Prototype", version="0.1.0",
                  description="Local-only owner account and DNS TXT verification; no live monitoring.")
    api.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"])

    @api.middleware("http")
    async def allow_loopback_only(request: Request, call_next):
        client = request.client.host if request.client else ""
        try:
            loopback = ipaddress.ip_address(client).is_loopback
        except ValueError:
            loopback = client == "testclient"  # Starlette TestClient only
        if not loopback:
            return JSONResponse(status_code=403, content={"detail": "Local development access only"})
        return await call_next(request)

    @api.middleware("http")
    async def no_cache_responses(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @api.exception_handler(OwnerError)
    async def owner_error(_request, exc: OwnerError):
        return JSONResponse(status_code=exc.status, content={"detail": str(exc)})

    def token_from_credentials(credentials: HTTPAuthorizationCredentials | None = Security(bearer)) -> str:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(401, detail="Authentication required")
        return credentials.credentials

    def get_me(token: str = Depends(token_from_credentials)) -> dict:
        return store.current_user(token)

    @api.get("/owner/health")
    def health():
        return {"status": "ok", "mode": "local-owner-onboarding", "live_monitoring": False}

    @api.post("/owner/register", status_code=201)
    def register(payload: Registration):
        return store.register(payload.email, payload.password.get_secret_value())

    @api.post("/owner/login")
    def login(payload: Login):
        result = store.login(payload.email, payload.password.get_secret_value())
        if "error" in result:
            raise HTTPException(401, detail=result["error"])
        return result

    @api.get("/owner/me")
    def me(user: dict = Depends(get_me)):
        return user

    @api.post("/owner/logout", status_code=204)
    def logout(token: str = Depends(token_from_credentials), _user: dict = Depends(get_me)):
        store.logout(token)

    @api.get("/owner/domains")
    def domains(user: dict = Depends(get_me)):
        return {"domains": store.list_domains(user["id"])}

    @api.post("/owner/domains", status_code=201)
    def add_domain(payload: AddDomain, user: dict = Depends(get_me)):
        return store.create_domain(user["id"], payload.domain)

    @api.post("/owner/domains/{domain_id}/rotate-challenge")
    def rotate(domain_id: str, user: dict = Depends(get_me)):
        return store.rotate_challenge(user["id"], domain_id)

    @api.post("/owner/domains/{domain_id}/verify")
    def verify(domain_id: str, user: dict = Depends(get_me)):
        claim = store.get_domain(user["id"], domain_id)
        if claim["verified_at"] is not None:
            return store._domain_public(claim)
        if claim["challenge_expires_at"] is None or claim["challenge_expires_at"] <= time.time():
            raise HTTPException(409, detail="Challenge expired. Rotate to obtain a new value")
        try:
            observed = lookup("_cybersentinel-verify." + claim["domain"])
        except LookupUnavailable:
            raise HTTPException(503, detail="DNS verification unavailable") from None
        return store.verify(user["id"], domain_id, observed)

    @api.delete("/owner/domains/{domain_id}", status_code=204)
    def delete(domain_id: str, user: dict = Depends(get_me)):
        store.delete_domain(user["id"], domain_id)

    return api


app = create_app()
