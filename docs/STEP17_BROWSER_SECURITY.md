# Step 17 - Browser Login Security Boundaries

## Security properties added

- OAuth2 Authorization Code flow with PKCE (S256), random single-use state,
  and a random per-login browser-binding cookie.
- HTTPS Auth0 tenant and JWK URLs are pinned to the configured issuer.
- The exchange happens only on the private FastAPI backend with the confidential
  Auth0 Web Application Client Secret. A proxy-disabled HTTPX client refuses
  redirects and enforces a request timeout.
- Signed RS256 access token must match configured API audience and issuer.
  Signed RS256 ID token must match configured Web Client ID, issuer, nonce and
  subject of that access token. JWT header algorithms are pinned.
- Browser receives only a random HttpOnly SameSite=Lax cookie, never an OAuth
  access or ID token. Sessions are hashed in volatile server memory.
- Form POSTs are protected with random per-session CSRF tokens. All values
  from stored domains and DNS challenges are HTML-escaped.
- Middleware enforces loopback client address, accepted Host header, no-store,
  no-referrer, nosniff, deny framing, and a restrictive CSP.
- Authenticated domain operations use Step 16 tenant-scoped PostgreSQL
  repository, which sets `cs.actor_id` locally per database transaction.

## Not supported or not assured

- This application is **private staging only**. Cookies are not Secure because
  the callback is an HTTP loopback URL, so they are NOT suitable for deployment
  over public HTTP. Never bind FastAPI to `0.0.0.0`; only one process/worker.
- Login flows and sessions reside in memory and are lost when process restarts.
  No session sharing, durable revocation, refresh flow, MFA enforcement, device
  management, production metrics, account lifecycle, anti-automation, or public
  domain ownership review is included.
- Clicking sign-out invalidates only the local browser session. It does not
  terminate the Auth0 SSO cookie or remotely revoke issued access tokens.
- We do not attempt a service-to-service access token or a public API.
- The agent ingestion service remains the Step 14 HTTPS staging prototype with
  SQLite storage and separate API keys. Hosted PostgreSQL telemetry and alerts
  are NOT migrated. No SaaS availability or attack detection claims are made.
- Unit tests simulate Auth0 exchanges and PostgreSQL stores; the real browser
  redirect, external Auth0 consent and networking require manual verification.

## Public-beta blockers

Use real HTTPS origin with Secure `__Host-` cookies, encrypted durable session
storage, CSRF/Origin enforcement, logout/revocation and MFA policies, secure
secret injection, domain linking between old/new databases, and a full security
review. Auth0 allowed callback URLs must use actual production domain; do not
reuse the local callback or expose localhost services.
