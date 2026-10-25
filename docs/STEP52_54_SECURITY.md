# CyberSentinel Steps 52-54 - Security boundaries

## Scope and evidence

This package tests a synthetic, two-tenant credential-custody facade, five-table
PostgreSQL row-level security canary, and fail-closed cutover state machine. It
uses the Step 47 disposable database, Step 49 credential broker and the existing
`CYBERSENTINEL_ISOLATED_PG_CI=1` + GitHub Actions local PostgreSQL guard.

- Step 52 exposes bounded, short-lived database connections and redacted fixture
  audit records. Password rotation and `NOLOGIN`+session termination delegate to
  the existing guarded Step 49 operator rehearsal. No secret is returned to an
  API consumer, logged, or saved to the project.
- Step 53 obtains an admin-owned fixture oracle, checks both genuinely
  role-bound logins under PostgreSQL RLS, and requires both shadow probes before
  canary activation. Wrong identity/fixture association causes a fail-closed
  rollback, even when both tenants have identical row counts.
- Step 54 explicitly reports `NO_GO` and never upgrades that decision because
  a test, static inspection, or prototype returns PASS.

## What rollback means here

Rollback seals this *experimental* credential facade and denies new requests.
It **does not** reverse deployed migrations (none are performed), invalidate
already-open PostgreSQL sockets, disable existing tenant roles in the database,
or automatically fail over to `cybersentinel_runtime`. For existing sessions,
only the separately exercised operator disable/termination action is relevant.

## Unresolved critical barriers

- Real Auth0 token -> tenant-bound connection routing is **not** integrated
  into `HostedStore` or `MonitoringStore`.
- No production secrets vault, just-in-time provisioning, HSM, rotation
  scheduler, admin authorization controls, revocation event bus, or connection
  pool drain orchestration.
- Legacy shared-role + mutable `cs.actor_id` remains in private staging.
- No real staging cutover, realistic failover, approved backup/restore, recovery
  objectives, independent security sign-off, or privacy/compliance review.
- This design does not authorize hosting an Internet-exposed tenant database or
  public multi-tenant beta.

**Release decision: NO-GO.** Keep Neon, Auth0, migration files and local MVP
unchanged. All database experiments are in a short-lived PostgreSQL 17 CI
service with synthetic data and roles.
