# Step 41 - tenant-specific PostgreSQL login role PoC and trust boundaries

## Existing issue

The application currently connects as the shared `cybersentinel_runtime` and
sets mutable PostgreSQL GUC `cs.actor_id`. A direct SQL client possessing that
shared password can change the GUC, impersonating an owner. Earlier CI explicitly
shows this weakness; it is not remediated by `FORCE ROW LEVEL SECURITY` alone.

## Isolated proof

The Step 41 CI fixture creates two *new*, nonprivileged login roles with unique
random passwords, a disposable schema, one owner mapping each, and a sample
`tenant_events` table. The mapping table permits SELECT but not modifications by
tenant roles and is itself guarded with FORCE RLS. The events table also uses
FORCE RLS and a policy that maps the immutable `session_user` login principal
to its owner UUID. A user-set `cs.actor_id` value has no authority in this new
policy. Roles are not members of one another, own no tables, and have neither
BYPASSRLS nor CREATEROLE. No SECURITY DEFINER functions are introduced.

Three database integration tests demonstrate: (1) GUC spoofing cannot change
visible owner, (2) cross-owner INSERT, mapping UPDATE and SET ROLE are denied,
(3) the old shared runtime role cannot access the new schema. These tests run
only on the disposable localhost PostgreSQL 17 service in GitHub Actions.

## Explicit limitations

- **Not integrated with real `cs` application tables or API.** Existing shared
  credential remains in use for Auth0 and ingestion staging; it is still
  vulnerable to the identified credential compromise scenario.
- Role-per-tenant provisioning requires privileged automation, lifecycle
  management, safe per-tenant credential distribution, pooling strategy,
  revocation, monitoring, incident response and secure secret storage.
- Loss of any tenant-specific credential still compromises *that tenant*.
- Admin/database owner compromise may bypass RLS; neither is modelled.
- Tenant separation does not itself fix arbitrary SQL injection, SSRF or insecure
  Auth0 identity mapping. It is one defense in depth layer.
- The CI demonstration has no production load, migrations of live tables or
  external penetration test. Do not run these fixture creation functions on
  Neon or on a non-disposable database.

**Public beta remains NO-GO.** Step 42+ needs an application/DB migration plan
with zero-downtime cutover, positive/negative authorization tests, rollback,
per-tenant key/secret rotation, and actual restore drills.
