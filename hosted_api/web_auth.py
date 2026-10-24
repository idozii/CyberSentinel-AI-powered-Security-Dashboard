"""Private Auth0 browser login helpers for the CyberSentinel hosted pilot.

All authorization codes and tokens stay on the server. An in-memory session
is deliberately process-local and lost at restart, not a distributed service.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
from jwt.exceptions import PyJWTError

from hosted_api.identity import Identity, IdentityRejected, OIDCVerifier
from hosted_api.settings import HostedSettings

FLOW_TTL = 300
SESSION_TTL = 1800
MAX_FLOWS = 100
MAX_SESSIONS = 100
COOKIE = "cs_private_owner"
FLOW_COOKIE = "cs_private_flow"


class WebLoginError(ValueError):
    pass


@dataclass(frozen=True)
class WebSettings:
    hosted: HostedSettings
    client_id: str
    client_secret: str
    callback_url: str

    @classmethod
    def from_env(cls) -> "WebSettings":
        return cls.validate(HostedSettings.from_env(),
                            os.getenv("CYBERSENTINEL_AUTH0_CLIENT_ID", ""),
                            os.getenv("CYBERSENTINEL_AUTH0_CLIENT_SECRET", ""),
                            os.getenv("CYBERSENTINEL_AUTH0_CALLBACK_URL", ""))

    @classmethod
    def validate(cls, hosted: HostedSettings, client_id: str, client_secret: str,
                 callback_url: str) -> "WebSettings":
        issuer = urlsplit(hosted.issuer)
        jwks = urlsplit(hosted.jwks_url)
        callback = urlsplit(callback_url)
        if (issuer.scheme != "https" or issuer.path not in ("", "/") or issuer.query or issuer.fragment
                or jwks.hostname != issuer.hostname
                or jwks.path != "/.well-known/jwks.json"
                or hosted.issuer != f"https://{issuer.hostname}/"):
            raise ValueError("Private portal requires exact Auth0 issuer and JWKS origin")
        if not re.fullmatch(r"[A-Za-z0-9_-]{8,256}", client_id):
            raise ValueError("Auth0 client ID is required")
        if not (16 <= len(client_secret) <= 2048) or any(ord(c) < 33 for c in client_secret):
            raise ValueError("Auth0 client secret is required (server-side only)")
        if (callback.scheme != "http" or callback.hostname != "127.0.0.1"
                or callback.port != 8007 or callback.path != "/auth/callback"
                or callback.query or callback.fragment or callback.username or callback.password
                or callback_url != "http://127.0.0.1:8007/auth/callback"):
            raise ValueError("Callback must be exact local staging URL")
        return cls(hosted, client_id, client_secret, callback_url)


def challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).rstrip(b'=').decode('ascii')


@dataclass(frozen=True)
class Pending:
    nonce: str
    verifier: str
    created: float
    flow_cookie_hash: str


@dataclass(frozen=True)
class UserSession:
    subject: Identity
    csrf: str
    expires: float


class MemorySessions:
    def __init__(self, clock=time.time):
        self.clock = clock
        self.lock = threading.RLock()
        self.flows: dict[str, Pending] = {}
        self.sessions: dict[str, UserSession] = {}

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode('ascii')).hexdigest()

    def cleanup(self):
        now = self.clock()
        for key, entry in list(self.flows.items()):
            if now - entry.created > FLOW_TTL:
                self.flows.pop(key, None)
        for key, entry in list(self.sessions.items()):
            if now >= entry.expires:
                self.sessions.pop(key, None)

    def begin(self) -> tuple[str, str, Pending]:
        with self.lock:
            self.cleanup()
            if len(self.flows) >= MAX_FLOWS:
                raise WebLoginError('Too many active login requests')
            state = secrets.token_urlsafe(32)
            flow_cookie = secrets.token_urlsafe(32)
            pending = Pending(nonce=secrets.token_urlsafe(32), verifier=secrets.token_urlsafe(48),
                              created=self.clock(), flow_cookie_hash=self._hash(flow_cookie))
            self.flows[self._hash(state)] = pending
            return state, flow_cookie, pending

    def consume(self, state: str, flow_cookie: str | None) -> Pending:
        if not isinstance(state, str) or not 32 <= len(state) <= 256:
            raise WebLoginError('Invalid login state')
        with self.lock:
            self.cleanup()
            pending = self.flows.pop(self._hash(state), None)
            if pending is None or self.clock() - pending.created > FLOW_TTL:
                raise WebLoginError('Login state expired or already used')
            if (not flow_cookie or not 32 <= len(flow_cookie) <= 256 or
                    not hmac.compare_digest(pending.flow_cookie_hash, self._hash(flow_cookie))):
                raise WebLoginError('Login browser binding mismatch')
            return pending

    def issue(self, subject: Identity, *, lifetime: int = SESSION_TTL) -> str:
        with self.lock:
            self.cleanup()
            if len(self.sessions) >= MAX_SESSIONS:
                raise WebLoginError('Too many active owner sessions')
            value = secrets.token_urlsafe(40)
            self.sessions[self._hash(value)] = UserSession(subject=subject,
                  csrf=secrets.token_urlsafe(32), expires=self.clock() + min(lifetime, SESSION_TTL))
            return value

    def get(self, value: str | None) -> UserSession | None:
        if not value or not isinstance(value, str) or not 40 <= len(value) <= 256:
            return None
        with self.lock:
            self.cleanup()
            return self.sessions.get(self._hash(value))

    def logout(self, value: str | None):
        if value and isinstance(value, str) and 40 <= len(value) <= 256:
            with self.lock:
                self.sessions.pop(self._hash(value), None)


class Auth0CodeExchange:
    def __init__(self, config: WebSettings, verifier: OIDCVerifier | None = None, jwks=None,
                 client=None):
        self.config = config
        self.verify_access = verifier or OIDCVerifier(config.hosted)
        self.keys = jwks or self.verify_access.jwks
        self.client = client

    def authorize_url(self, state: str, pending: Pending) -> str:
        args = {
            'response_type': 'code', 'client_id': self.config.client_id,
            'redirect_uri': self.config.callback_url,
            'scope': 'openid profile', 'audience': self.config.hosted.audience,
            'state': state, 'nonce': pending.nonce,
            'code_challenge': challenge(pending.verifier), 'code_challenge_method': 'S256',
        }
        return self.config.hosted.issuer + 'authorize?' + urlencode(args)

    def exchange(self, code: str, pending: Pending) -> Identity:
        if not isinstance(code, str) or not 1 <= len(code) <= 4096:
            raise WebLoginError('Invalid authorization code')
        payload = {
            'grant_type': 'authorization_code', 'code': code,
            'redirect_uri': self.config.callback_url, 'client_id': self.config.client_id,
            'client_secret': self.config.client_secret, 'code_verifier': pending.verifier,
        }
        try:
            if self.client is None:
                with httpx.Client(timeout=5.0, follow_redirects=False, trust_env=False) as c:
                    response = c.post(self.config.hosted.issuer + 'oauth/token', data=payload)
            else:
                response = self.client.post(self.config.hosted.issuer + 'oauth/token', data=payload)
            if response.status_code != 200 or len(response.content) > 16384:
                raise WebLoginError('Authorization code exchange rejected')
            tokens = response.json()
            if not isinstance(tokens, dict) or tokens.get('token_type', '').lower() != 'bearer':
                raise WebLoginError('Invalid token response')
            access_token, id_token = tokens.get('access_token'), tokens.get('id_token')
            if not isinstance(id_token, str) or not 50 <= len(id_token) <= 8192:
                raise WebLoginError('Missing ID token')
            identity = self.verify_access.verify(access_token)
            header = jwt.get_unverified_header(id_token)
            if (header.get('alg') != 'RS256' or not isinstance(header.get('kid'), str)
                    or not 1 <= len(header['kid']) <= 256
                    or any(p in header for p in ('jku', 'x5u', 'crit'))):
                raise WebLoginError('Invalid ID token header')
            signing_key = self.keys.get_signing_key_from_jwt(id_token)
            claims = jwt.decode(id_token, signing_key.key, algorithms=['RS256'],
                                issuer=self.config.hosted.issuer, audience=self.config.client_id,
                                options={'require': ['iss', 'aud', 'sub', 'iat', 'exp', 'nonce']},
                                leeway=30)
            if (claims.get('nonce') != pending.nonce or claims.get('sub') != identity.subject
                    or claims.get('iss') != identity.issuer):
                raise WebLoginError('ID token does not match login request')
            return identity
        except WebLoginError:
            raise
        except (httpx.HTTPError, ValueError, TypeError, KeyError, PyJWTError, IdentityRejected, OSError) as exc:
            raise WebLoginError('Auth0 login could not be verified') from exc
