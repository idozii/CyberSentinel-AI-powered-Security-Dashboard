# CyberSentinel - Hosted Ingest Staging Security Model

## Threat boundary

The public staging surface is **only** `POST /agent/v1/ingest`, behind Caddy HTTPS. The reverse proxy routes to `127.0.0.1:8004`, where a dedicated ASGI app exposes one route. Administrative routes are in another ASGI app bound to `127.0.0.1:8002`, which must remain unreachable from the public Internet. A private SSH tunnel is the current recommended admin path.

### Security controls implemented

- Agent requires explicit `--server https://<hostname>` and `--allow-remote-host <same hostname>` to enable remote sends. HTTPS must be on port 443 with standard certificate hostname validation. Non-HTTPS, arbitrary ports, user-info, paths, query strings and IP literals are rejected.
- Agent disables environmental HTTP proxies and HTTP redirects, reducing accidental disclosure of the Bearer API key to other origins.
- Caddy uses exact POST path routing, 32KB maximum request size and 404 fallback. Owner API is not in the upstream configuration.
- Ingest-only backend has no owner routes or Swagger/OpenAPI endpoints. It validates bearer keys and domain authorization through the existing Step 11 TelemetryStore.
- Both services use localhost listeners and the same staging SQLite database. Owner-specific event/alert isolation and retention from Steps 10-12 remain in effect.
- The agent still minimizes telemetry and uses HMAC pseudonymous source identifiers; raw URL queries, cookies, passwords and raw IPs are not transmitted.

### Important remaining gaps

1. Caddy is an HTTPS termination point; the backend hop is plaintext loopback on the **same host**. If it crosses machines, this pattern is invalid until reworked.
2. Remote hostname allowlisting is a local operator policy; it is not a DNS pin. Configure the domain and hosting only under authorized administration. Agent requires working system CA trust; never disable certificate verification.
3. A single SQLite database and synchronous ingestion are not yet a production telemetry backend; large traffic may saturate locks or storage.
4. The existing 300 events/minute/domain limit is for the prototype and does not replace a global WAF/rate limiter, authenticated quotas, DDoS controls or monitoring.
5. Owner accounts still use local passwords and sessions; no MFA, hosted identity provider, email verification, legal notices, tenant billing, secret-management platform or consent workflow is included.
6. DNS TXT challenge proves present technical control of a record; it is not permanent proof of legal ownership. Require re-verification and revocation policies before self-service hosting.
7. Event replays can be idempotent but old queued events will be rejected after the server's 5-minute freshness limit. Do not discard them without an explicit operator decision.
8. Caddy config and systemd templates are examples. `scripts.step14_preflight` verifies selected text patterns, not complete syntax, firewall safety or end-to-end HTTPS issuance. Verify them on the intended server with `caddy validate` and live checks.
9. Do not use the current Isolation Forest to block traffic or promise robust real-world intrusion detection. Existing alert rules are advisory and can have false positives.

## Next step (Step 15)

Design hosted owner UI and identity boundaries, database migrations to PostgreSQL, per-owner service isolation, reliable async background jobs, consent and data retention policies, secret rotation, abuse controls, security monitoring and deployment gates. Launch externally only after review and permission to operate the service.
