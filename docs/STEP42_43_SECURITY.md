# Steps 42-43 - Threat model and limitations

## Stronger property demonstrated in PostgreSQL CI

The roles `cs41_..._a` and `cs41_..._b` are individually authenticated by
PostgreSQL. A forced RLS policy uses `session_user`, and the immutable
admin-owned `tenant_logins` mapping determines an owner UUID. Client-side
`set_config('cs.actor_id', ...)` cannot change a PostgreSQL login role.

The temporary adapter performs a defensive login identity check, then selects
or inserts only synthetic summaries. It cannot accept an arbitrary tenant ID
from an API request. It refuses any environment except the exact ephemeral
GitHub Actions database fixture. No raw requests, personal data, real keys or
Neon credentials are included.

## Properties not proven

- `HostedStore`, `MonitoringStore`, Auth0, or the existing `cs` policies have
  **not** been migrated to tenant login roles. Old shared-runtime actor spoofing
  remains a threat if its SQL credential leaks.
- No credential broker, secret distribution, per-tenant connection pool,
  provisioning/deprovisioning or key rotation design has been validated.
- Current privileges and identity mapping must undergo independent review,
  including escalation through `SET ROLE`, ownership, grants and role reuse.
- This experiment is not evidence of security on Neon, production traffic,
  concurrency, outages, monitoring, or disaster recovery.
- A successful GitHub CI job validates only the two disposable tenant fixtures.

## Release and rollback

**NO-GO for public beta.** Keep staging unchanged. Roll back this development
change by reverting the feature commit; no database schema change exists.
A future migration must have a dedicated disposable rehearsal, backup and
restore evidence, controlled cutover, audited privilege review, and a tested
return path to the original staging configuration before operating publicly.
