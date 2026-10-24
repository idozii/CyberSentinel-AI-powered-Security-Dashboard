# CyberSentinel Step 16 - PostgreSQL and Managed Identity Security

## Exactly what this stage delivers

- A **separate localhost-only** FastAPI pilot at port 8006, using a configured external OIDC issuer and PostgreSQL.
- Cryptographic validation of RS256 JWT **access tokens**, with `iss`, `aud`, `sub`, `exp`, `iat`, a required `kid`, and a statically configured HTTPS JWKS endpoint. No `alg=none` or HS256 fallback.
- PostgreSQL migration 001 with an immutable SHA-256 checksum, an identity table, a domain claim table, owner-scoped SQL policies, and `FORCE ROW LEVEL SECURITY`.
- Two distinct PostgreSQL roles: an administrative migration login that owns tables and an unprivileged `cybersentinel_runtime` application login. The runtime role must not be superuser, table owner, or have `BYPASSRLS`.
- Transaction-local actor assignment using `set_config('cs.actor_id', <id>, true)` before accessing tenant rows. Each request's DB connection is opened within a transaction and closed at the end of the operation.
- DNS TXT claim creation and verification for the PostgreSQL staging path, using the prior local project's public hostname restrictions and DNS resolver.
- A CI PostgreSQL service that exercises the actual runtime role, isolated identities/domains, missing actor deny, unique domain ownership, and DNS TXT verification.

## Critical limitations

1. **Not public production auth.** An administrator must configure a supported identity provider and obtain a valid access token externally. This stage does NOT implement OAuth authorization-code + PKCE in the browser, login redirects, refresh tokens, MFA, account recovery, email verification, consent, or customer onboarding.
2. **Do not migrate SQLite files by copying them to PostgreSQL.** No data migration from the Step 10-15 SQLite owner database is delivered. The Step 16 PostgreSQL pilot has separate identities and domain claims only. **Existing agent keys, telemetry, alerts, and ownership are not migrated or linked.**
3. **Remain loopback only** (`127.0.0.1:8006`) and access through SSH tunneling. The Step 14 ingest endpoint and Step 15 local portal continue to use SQLite as before. Never add a Caddy route for the Step 16 owner API yet.
4. **RLS is defense in depth.** A superuser, a `BYPASSRLS` role, or some SQL injection paths involving tampering with actor context can defeat isolation. Use strict statement parameterization, least privilege, no dynamic SQL from user input, and separate migration credentials.
5. The application DB role must be dedicated and unable to create/alter schema, own tables, or change its role. Never set an actor ID from a submitted header. It must derive from a validated OIDC `iss` and `sub` pair.
6. Use a provider-issued **access token with this API as audience**. ID tokens intended for another client are not a substitute. Configure separate staging issuer/audience; never log tokens, credential DSNs, verification challenges or raw IP addresses.
7. The OIDC JWKS URL is admin-pinned over HTTPS; use a supported provider's discovery documents to identify it, verify hostname and isolate outbound network access. The `PyJWKClient` may fetch/refresh keys on demand; rate limit and monitor failed verifications before a public release.
8. Always use database TLS verification for remotely hosted PostgreSQL. The sample GitHub Actions job uses cleartext only inside its ephemeral local CI container environment.
9. DNS control does not establish legal ownership, and it can change after verification. Add proof renewal, abuse management, recovery, revocation, and audit logging before live customer access.
10. The staging code uses UUIDv5 mapping for a stable identity key, and stores issuer + subject, not email. It does not remove the need for privacy notices, data retention policy and delete/export workflows.

## PostgreSQL RLS validation

Before enabling any public traffic, confirm that:

- `SELECT rolname,rolsuper,rolbypassrls FROM pg_roles WHERE rolname='cybersentinel_runtime'` returns `false` for the latter two columns.
- `SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid IN ('cs.identities'::regclass, 'cs.domains'::regclass)` shows both flags true.
- Without an actor context the runtime role sees no identities/domains.
- Under distinct validated OIDC subjects, each user sees only their own claims.
- Restarting or reusing connections does not retain the prior user's actor context.

### Database backup and operations

The Step 15 SQLite backup cannot back up PostgreSQL. Use a provider-managed Postgres backup/PITR plan or `pg_dump` with a tested restore and encryption. Do not upload dumps to Git or place credentials in CI artifacts.

## References

- PostgreSQL Row Security Policies: https://www.postgresql.org/docs/current/ddl-rowsecurity.html
- PyJWT algorithm and validation requirements: https://pyjwt.readthedocs.io/en/latest/api.html
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
