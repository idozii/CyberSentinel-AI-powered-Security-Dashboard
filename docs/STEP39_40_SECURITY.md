# Security boundary assessment - Steps 39-40

## Precisely what is established

- SQL uses FORCE RLS, and application API checks are tenant-scoped for normal authenticated requests.
- SQL policies read `current_setting('cs.actor_id', true)`; `HostedStore._set_actor` uses transaction-local `set_config`.
- PostgreSQL custom GUCs like `cs.actor_id` are not inherently protected credentials. The same SQL login with its password can set another value. A direct credential compromise can therefore sidestep the app's identity mapping by acting as any owner UUID known to the attacker.
- Step 39's CI witness demonstrates this using two synthetic owners in an *isolated* PostgreSQL 17 database. No other accounts or public services are probed.

## What is NOT established

- Not a remote user authentication bypass of Auth0, and not proof an anonymous visitor can reach PostgreSQL. The assumed attacker already has a runtime DB credential/direct SQL connectivity.
- Not a finding of a live exploit of Neon or a claim that staging data has been compromised.
- No database-enforced tenant authorization for compromised shared credentials is implemented by this patch.
- RLS and field validation still mitigate ordinary API access but do not change the direct-SQL threat model.

## Required design work before public beta

Choose and review a genuine database-enforced tenant trust boundary: for example, separate per-tenant database principals with grant and revocation policies, or a trusted broker/verified signed claim that the untrusted runtime SQL principal cannot forge. Evaluate connection pooling, role lifecycle, blast radius, secret handling and operational complexity. Replace the positive spoof witness with regression tests showing a stolen tenant-scoped credential **cannot** read another tenant. Have the design independently reviewed before changing staging migrations.

Keep database access private; do not log or commit DSNs, tokens or raw telemetry. Run only disposable localhost integration tests; the release gate must stay NO-GO until independently reviewed public beta controls exist.
