# CyberSentinel Steps 55-57 - tenant boundary architecture review

**Status: CI-only proof. NO-GO for public multi-tenant beta.**

## Current source of truth

- `HostedStore` and `MonitoringStore` still use `cybersentinel_runtime` with a mutable `cs.actor_id` transaction setting. Their risk is **not fixed** by Steps 55-57.
- Steps 41-54 supplied disposable PostgreSQL role-bound isolation, credential custody simulations and an operator-driven cutover rehearsal.
- This change does **not** alter existing database migrations, Auth0 tenant configuration, Neon staging, or deployed API routes.

## Step 55 - Tenant session admission

`hosted_api/tenant_session_boundary.py` exposes a small **CI-only** admission layer around `DisposableCredentialCustody`:

1. A bearer is verified by the existing synthetic verifier/allowlisted broker before a tenant index is chosen. The request cannot supply `owner_id`, DB role or DSN.
2. Admission is bounded independently per synthetic tenant, with fail-closed denial on excess capacity or unknown identity.
3. The session must report `session_user == current_user == provisioned login role` before it is used.
4. Slots are returned in a `finally` path, including on SQL errors and identity failures.
5. Operator disable immediately blocks **new** admissions, then calls the protected Step 49 `NOLOGIN` plus connection-termination drill; failure leaves admission blocked.
6. `seal()` only rejects future access. It cannot promise to terminate in-flight sessions, remote worker pools, or already-issued tokens.

This is bounded admission, **not** a production connection pool or distributed admission control. A lock only protects the current Python process; distributed nodes would require a reviewed broker and globally coordinated revocation.

## Step 56 - Isolated canary

`IsolatedTenantBoundaryCanary` performs fixed read-only counts over the five `cs.*` tables while using an independently authenticated PostgreSQL login. It never accepts SQL identifiers or tenant IDs from the request. The CI job checks tenant isolation, mutable-GUC spoof resistance, overload rejection, invalid identities and role disable while another tenant stays available.

The prototype is deliberately not wired to the hosted FastAPI process, Streamlit Cloud, Auth0, or public agent ingest.

## Step 57 - NO-GO gate

`python -m scripts.step57_architecture_gate` verifies the patch and CI registration; its status `ready_for_ci_review` means only that **source prerequisites exist**. It does not establish a real PostgreSQL test result or deployment authorization. The release decision remains `NO_GO`.

## Design decisions required before staging

- Threat-model the identity provider, JWT verifier trust boundary, service-to-service authorization, admin/operator provisioning and tenant impersonation.
- Choose a production secret vault; separate owner, broker, tenant login, migrations and observability privileges. Never hand tenant passwords/DSNs to clients.
- Design per-tenant connection pooling, asynchronous traffic isolation, concurrency limits, pool invalidation, rotation and emergency disconnect across workers.
- Define database schema and RLS migration cutover with backup, restore, rollback and explicit conflict resolution for existing tenant rows.
- Require verified DNS ownership for public monitoring, observability, alerting, privacy limits and an independent security review.

## Hard blockers

**Do not** connect this CI prototype to Neon or real Auth0. **Do not** claim the mutable `cs.actor_id` vulnerability is resolved in the currently deployed stores. **Do not** treat PASS on a disposable DB as a production security attestation. Do not merge a PR if any existing CI job fails or is unexpectedly skipped.
