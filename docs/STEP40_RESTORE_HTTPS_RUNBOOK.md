# Step 40: Restore and HTTPS runbook (design only)

This document is a checklist for a *future* authorized staging/beta. No commands here were executed against Neon or production. The Step 40 report performs **zero network calls**. Never publish the localhost Demo or attach it to a public reverse proxy.

## 1. Pre-backup controls

- Assign an operator responsible for a restore drill and select **disposable isolated Postgres** with synthetic tenants; do NOT choose the active Neon branch.
- Choose RPO/RTO, backup frequency, encryption, retention, access rights, and restore destination; document approval.
- Export `CYBERSENTINEL_TEST_PG_ADMIN_DSN` **only** for a dedicated disposable local database. Never paste it into chat or logs.
- Ensure PostgreSQL client tool versions are compatible, and a role strategy exists to restore schema/table grants and tenant isolation correctly.

## 2. Disposable Postgres logical backup and restore drill - operator commands

Illustrative commands for a dedicated disposable local PostgreSQL instance, not for the application Neon database. All output paths should be owner-only and outside the Git repository.

```bash
umask 077
mkdir -p "$HOME/.local/share/cybersentinel-drill"
# Set PG* connection environment variables locally, not in Git.
# Choose the disposable local database, never Neon or production.
pg_dump --format=custom --schema=cs --file="$HOME/.local/share/cybersentinel-drill/synthetic.dump" "$CYBERSENTINEL_TEST_PG_ADMIN_DSN"
# Provision a separate empty LOCAL restore database; this command is illustrative.
# pg_restore must target that separate new DB, never the source.
pg_restore --no-owner --no-acl --dbname="$CYBERSENTINEL_TEST_PG_RESTORE_DSN" "$HOME/.local/share/cybersentinel-drill/synthetic.dump"
```

Before running, manually verify source and destination DSNs both resolve to **localhost** and differ in database name. Restore into a database with expected roles and schemas. A dump may include sensitive tenant rows: use synthetic data only, protect file permissions and delete the artifact after the drill. Never use `--clean` against source/staging.

## 3. Verification evidence (must be measured, not assumed)

- Verify restored table counts for all five tables, RLS ENABLE/FORCE, grants, indexes, migration version markers and foreign keys.
- Run two-tenant normal-access and stolen-runtime-credential threat tests on the restored instance, and record limitations.
- Record start/end UTC, restore time, observed RTO, possible loss window/RPO, operator sign-off, checksums stored privately and deletion evidence.
- A successful **synthetic** restore does not establish a production recovery guarantee.

## 4. HTTPS deployment review (future only)

- Own and verify a DNS domain; use trusted HTTPS certificate issuance and renewal, canonical hostname, HSTS only after review.
- Separate owner/admin and agent ingestion exposure. Do not forward raw Auth0 tokens or secrets to logs; enforce request size, rate limits and validation.
- Review Forwarded/X-Forwarded-For trust boundaries, proxy redirects, cookie Secure/SameSite settings, CSP, CORS and CSRF for real origins.
- Confirm ingress is private by default, TLS 1.2/1.3 policy, trusted proxy and no accidental public 8007/8008/8019 bindings.
- Monitor failures, queue backlog, 5-minute event freshness, backup health, restore readiness and incident response.
- Secure tenant privilege redesign and independent penetration testing must precede public beta authorization.

## 5. Stop conditions

If domain ownership, tenant compromise resilience, actual separate restore, HTTPS review, privacy approval, on-call operations or independent assessment is missing, public beta is **NO-GO**. A green local CI or a self-attested JSON checklist must never override this stop condition.
