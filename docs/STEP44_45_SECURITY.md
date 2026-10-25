# CyberSentinel Steps 44-45 - Security boundaries

## What is included

- A disposable PostgreSQL 17 role inspector for Step 41 tenant fixtures.
- Checks for `NOSUPERUSER`, `NOBYPASSRLS`, `NOCREATEDB`, `NOCREATEROLE`, `NOINHERIT`, and least-privilege grants.
- Separate synthetic tenant password rotation and `NOLOGIN` disable drills, with negative login tests.
- CI workflow integration and an explicit offline public-beta no-go gate.
- All role DDL is protected by the Step 41 ephemeral GitHub CI guard and uses quoted SQL identifiers.

## What is NOT included or proven

- No access to Neon or Auth0, and no migration of existing `cs.*` tables.
- No trusted identity-to-role broker, managed secret vault, deprovisioning orchestration, production key distribution, or rate-limited connection pool.
- Rotation and `NOLOGIN` block **new authentication only**. They do not automatically terminate existing database sessions. A future design must handle connection draining/termination, cache invalidation, and sessions authenticated with prior secrets.
- A passing CI proves fixture behavior, not real-world resilience to credential compromise or all SQL privilege escalation paths.
- No evidence of scalable tenants, backup restoration of live datasets, incident response, independent penetration testing, or regulatory approval.

## Release decision

**NO-GO** for public multi-tenant monitoring. Continue to keep `HostedStore`/`MonitoringStore` on private staging only. The shared `cybersentinel_runtime` + caller-set `cs.actor_id` pattern remains a critical compromise boundary.

## Next controlled change

Design an independently reviewed trusted identity broker and per-tenant credential custody model, perform the full `cs.*` policy migration and rollback on a completely isolated PostgreSQL database, then require cross-tenant and outage drills prior to any beta decision.
