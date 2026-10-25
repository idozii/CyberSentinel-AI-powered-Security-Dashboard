# CyberSentinel Steps 46-48 - Scope and threat model

## What this patch implements

- Step 46: a narrow, injectable OIDC-verifier-to-allowlisted-role mapping prototype, with two synthetic identities and no credential distribution.
- Step 47: a fresh randomly named PostgreSQL database created only in the GitHub Actions disposable PostgreSQL 17 service. It applies the existing unmodified `001_initial.sql` and `002_monitoring.sql` migrations, then adds role-bound RLS policies to all five `cs.*` tables. It verifies that setting `cs.actor_id` to another owner does not change row visibility.
- Step 48: tests mapping write denial, SET ROLE denial, cross-owner update denial, reversibility of additive policies, preservation of original RLS policies and test rows, removal of disposable roles, and unconditional fixture teardown.
- Existing Streamlit public dashboard, localhost SOC and production/staging Neon schema are unchanged.

## Important boundaries

- The mapping broker is a design prototype, NOT a trusted identity broker deployed to a server. Real security requires a reviewed, fixed OIDCVerifier configuration, trusted binding provisioning and verification that no untrusted process can inject an alternative verifier or mapping.
- The test database is a fresh CI-only copy of the SCHEMA, not a restore of user data, not a simulation of Neon permissions, and not a proof of backup/restore safety for real datasets.
- No role credential vault, tenant-level connection pool, broker-side rate limiting, audited revocation, session termination or automated provisioning service is implemented.
- Existing `HostedStore` and `MonitoringStore` still use mutable `cs.actor_id` via the shared runtime role. They are NOT cut over.
- Additive policies prove a security property for new roles in this isolated database; they are not a replacement migration for existing `cs.*` tables.
- No staging or production DSN may be passed to this patch. All destructive database operations require Step 41's explicit GitHub Actions disposable guard.
- Never print DSNs, role passwords, session credentials, or user JWTs in CI logs.

## Acceptance criteria

1. Both offline and PostgreSQL integration CI jobs PASS (not skipped).
2. A real login sees exactly its own row in each of the five tables, including after a spoofed actor setting.
3. Two login roles lack mapping UPDATE, role-switching and cross-owner UPDATE privileges.
4. Reverting the additive policies leaves baseline policies and synthetic rows unchanged.
5. Public beta decision remains NO-GO, regardless of green CI.

## Next engineering decision

Steps 49-51: independently review identity verification and credential custody, build least-privilege provisioning and connection pooling in a new disposable environment, then run a reversible application canary with failure recovery. Do not connect to Auth0 or Neon until review and approval.
