# CyberSentinel Steps 58-63 - Isolated HTTP vertical slice

## Scope and risk boundary

This change creates a **separate, unmounted, CI-only FastAPI application** that proves one narrow read-only request path:

`RS256 signed access token -> existing OIDCVerifier -> provisioned identity-to-role broker -> TenantSessionBoundary -> PostgreSQL login role -> FORCE RLS -> five-table synthetic overview`.

There is **no `factory()`**, no module-level ASGI `app`, and **no registration** in `hosted_api/web.py`, `hosted_api/main.py`, `hosted_api/ingest.py`, Streamlit, Docker or deployment. The app must be created explicitly via `create_disposable_http_pilot(boundary, enabled=True)` and only with a guarded disposable PostgreSQL fixture. The CI guard is a developer safety condition, **not** a security boundary against an administrator changing environment variables.

## Step coverage

- **58**: Disabled-by-default CI-only FastAPI app creation; validated fixture and fail-closed local test guard.
- **59**: Real RSA-signed JWT is validated by the existing pinned OIDC verifier in PostgreSQL CI. No decoded/unverified claims determine the DB role.
- **60**: Reuses Step 55 tenant admission; `session_user/current_user` must match the already-provisioned PostgreSQL login role.
- **61**: HTTP `GET /internal/v1/tenant/overview` returns only counts for the five existing `cs.*` tables. No query, body, dynamic SQL identifiers, tenant selector, or mutation route is accepted.
- **62**: Disposable PostgreSQL tests run through ASGI TestClient with two real PostgreSQL login roles, valid/invalid RS256 JWTs, rate limiting by tenant, disable/revoke, outage and cross-tenant isolation.
- **63**: CI registration and an honest security evidence gate; `NO_GO` for private staging cutover and public multi-tenant beta.

## Security constraints

- No PostgreSQL passwords, raw bearer tokens, DSNs, OIDC subjects or role names are returned in responses.
- HTTP errors are generic. Known admission errors return 401; backend unavailable returns 503. The fixture-only capacity denial is intentionally indistinguishable at the HTTP layer; production can define a controlled 429 contract after review.
- TrustedHost and loopback middleware reject remote hosts and remote peer addresses. TestClient `testclient` peers are accepted only for this CI-only app.
- Cache disabled and common browser hardening headers enabled. Public docs/OpenAPI paths disabled.
- No real Auth0 connection, managed secret vault, real tenant provisioning, DNS ownership change or Neon migration.
- Only synthetic owner data in random disposable CI databases.
- The existing legacy `HostedStore` and `MonitoringStore` still use shared `cybersentinel_runtime` and mutable `cs.actor_id`; stolen-credential tenant spoofing remains a serious risk.

## Review notes

Before ANY real staging integration, design the operator-authorized role provisioning and secret custody system; review dynamic credential lookup and pool isolation; make tenant-disable effective across all service replicas; add authenticated administrative actions, HTTPS, realistic workloads, timeouts, load testing, incident procedures and independent security review. A passing disposable CI integration check does **not** prove those properties.

Keep `local-mvp-v1.0.0` demo and Streamlit showcase untouched. No public beta authorization is provided by this patch.
