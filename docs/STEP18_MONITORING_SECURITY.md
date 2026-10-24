# Step 18 - Private PostgreSQL monitoring security boundary

## Scope

Step 18 provides a **localhost-only PostgreSQL pilot** for DNS-verified Auth0
owner domains, agent keys, redacted telemetry and deterministic threshold alerts.
It is **not a public SaaS service or a production detector**. Existing Step 11-15
SQLite APIs and their data stay unchanged. There is no silent import or deletion.

## Trust boundaries

- Browser: Auth0 Authorization Code + PKCE and the existing in-memory session.
  All key creation/revocation and alert-acknowledge POSTs require that session
  and a same-session CSRF secret. HTTPS/public cookies are NOT configured.
- Database: `cybersentinel_runtime` must be non-superuser and non-BYPASSRLS.
  `HostedStore._set_actor` fail-closes on another role and sets `cs.actor_id`
  **transaction-locally**. All three new tables enable and FORCE RLS.
- Agent: `csp_<owner-uuid-hex>_<random>` tokens include an untrusted owner UUID
  solely to choose the transaction's RLS actor. This prefix is NOT authority.
  Authorization checks a SHA-256 token digest against the verified domain
  and active key **inside that actor's RLS scope**. PostgreSQL stores only the
  digest and never exposes it in owner UI responses.
- Agent ingress listener defaults to `127.0.0.1:8008` and has no public Caddy
  route. Treat tokens as credentials. Never bind this listener to `0.0.0.0`.
- Ingest limits: max 25 events per request, 32KB body, 300 events/domain/minute,
  5-minute event time skew, 7-day on-ingest retention. No global rate limiting,
  distributed quotas, request authentication hardening, or monitoring of stalled
  agents is claimed. For production, add proper edge quotas and observability.
- Privacy: source is HMAC pseudonym (32 hex), coarse path group and metadata;
  no raw IP, URL, cookies, bodies, passwords, headers or browser tokens.
- Delivery: agent-generated `event_id` is unique per domain; retry is idempotent.
  Ingest, alert updates and key last-use update commit atomically. Transactions
  serialize per domain through an advisory transaction lock. A revoked key is
  rejected; an in-flight transaction that already locked the key completes.
- Monitoring rules: advisory thresholds only, not proof of an attack; repeated
  401 login (5), HTTP 404 burst (8), HTTP 5xx burst (5), and requests (40) in
  60 seconds grouped by pseudonymous source.

## Deployment constraints and caveats

- Apply checksum-checked migration `002_monitoring.sql` only after a backup and
  after migration 001. Never modify previously applied migrations.
- Migration/admin DSN must NEVER be used by `MonitoringStore`, web or agent API.
- PostgreSQL CI integration uses ephemeral PostgreSQL 17 with a separate runtime
  user and proves isolation across two identities, token revocation, idempotency,
  alert acknowledge, and the RLS-default-deny behaviour.
- Only a new PostgreSQL pilot is provided; the existing public HTTPS ingest
  example (Step 14) still sends to the SQLite backend and MUST NOT be re-pointed
  automatically to the Step 18 pilot.
- Reversible app change: stop `hosted_api.ingest`, revert code/config, keep the
  database schema and rows intact until a separately approved rollback. Do not
  run `DROP TABLE` against the live Neon project to roll back application code.
- No cross-database migration of local owner IDs exists. New OIDC identities
  have different identifiers; issue fresh agent keys and verify real DNS claims.
