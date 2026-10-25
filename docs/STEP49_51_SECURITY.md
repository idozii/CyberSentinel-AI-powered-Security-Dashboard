# CyberSentinel Steps 49-51 - Security boundaries

## Scope

A **CI-only** proof using two synthetic identities and two independent PostgreSQL
login roles inside a new random `cs46_*` database. It uses the Step 47 five-table
`cs.*` additive RLS migration and destroys the database after each scenario.

- Step 49: a verified identity-to-role resolver, whose verifier is injected by
  the test harness. The role and its database password are never selected by
  the HTTP/request caller. The broker uses temporary in-memory synthetic
  credentials and never returns connection strings, admin secrets or passwords.
- Step 50: one-use connections, role-scoped synthetic password rotation, and
  `NOLOGIN` followed by server-side termination of existing sessions for exactly
  the chosen disposable PostgreSQL login. Authentication failures do not
  disclose credentials or identity claims.
- Step 51: a minimal simulated application canary for domain/alert/event
  queries and alert acknowledgement. RLS protects all five baseline tables.
  Negative tests include unknown tokens, cross-tenant alert IDs, changes to
  mutable `cs.actor_id`, and ownership changes.

## Important limitations

- The verifier in `test_step49_51_pg.py` is a synthetic stub. No actual bearer
  token signature is validated by these tests. Real `OIDCVerifier` integration,
  token-to-role provisioning and revocation require independent engineering.
- In-memory passwords are only acceptable for disposable CI fixtures. There is
  **no secret vault, secure distribution, lease expiry, broker-to-database TLS
  plan, HSM, audit trail, multi-process coordination, connection pool, rate
  limiting, or operator authorization**.
- The administrative methods `_ci_operator_rotate` and
  `_ci_operator_disable_and_terminate` are **not** an operator API. Production
  must have authenticated, audited operator authorization and recovery plans.
- Credential rotation does not revoke already authenticated sessions. The
  disable exercise first commits `ALTER ROLE NOLOGIN`, then terminates matching
  sessions by both `datname` and `usename`. Termination is not a substitute for
  comprehensive revocation, cache draining or cross-node coordination.
- The `HostedStore` / `MonitoringStore` remain unchanged and still use the
  shared runtime `cs.actor_id` security context. Compromise of those credentials
  remains a serious multi-tenant risk.
- NO migration of Neon, Auth0 or real customer data, no public routes, and no
  release to production or public multi-tenant monitoring.

## CI and merge criteria

1. On the fresh feature PR, Python 3.12 + 3.13 must run the new offline tests.
2. The PostgreSQL 17 integration job must execute **not skip** the new test
   class, all four tests, alongside every existing Step 41-48 RLS regression.
3. Existing NGINX and Docker smoke checks must remain green.
4. CI `Step 51` gate must say `public_beta_allowed: false`.
5. Do not merge on a failing, skipped or inconclusive security job.

## Next stage

Only after this isolated canary passes, plan Steps 52-54: real broker design
review, authenticated secret custody and a reversible staging cutover rehearsal
on a sanitized/restored disposable database, followed by independent security
review. Do not connect this prototype to live Neon or Auth0.
