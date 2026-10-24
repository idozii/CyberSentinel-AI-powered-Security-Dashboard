# Step 15 - Private Operations Security Design

## Scope and trust boundary

The Step 14 isolated public HTTPS ingest API remains unchanged. Step 15 introduces NO public owner management endpoints. Private Owner API is bound to 127.0.0.1:8002 and the Streamlit Owner Portal to 127.0.0.1:8503. Caddy continues to proxy only POST /agent/v1/ingest to 127.0.0.1:8004. A trusted operator reaches the portal via SSH forwarding.

This is one-host staging, not a hosted multi-tenant SaaS. Existing owner credentials are in a SQLite file, not in a managed IdP or PostgreSQL. SSH tunnel access is only appropriate for a small set of trusted operators.

## Backup threat model

The owner database can contain account email addresses, password hashes, hashed sessions and agent keys, minimized telemetry and rule alerts. Backups therefore contain sensitive material even though event payloads do not include raw IPs. Keep the backup directory 0700, backup file 0600, encrypt copies before off-host transfer and control read access. SQLite online backup produces a consistent snapshot while services write; copying a live SQLite database with `cp` is not an acceptable replacement. A SHA256 checksum detects accidental changes but does NOT encrypt data or prove authenticity.

The restore drill opens a source backup read-only, copies it to a new temporary SQLite file and checks quick_check, foreign keys and required tables. It does not restore production traffic, check application versions across database migrations or replace the active database. A comprehensive recovery strategy needs scheduled restore testing and documented RPO/RTO objectives.

## Retention

The dry-run is default and counts records eligible for cleanup. `--apply` removes expired sessions, telemetry older than 7 days by `received_at`, alerts older than 7 days by `window_start`, and pending expired TXT challenges. It preserves verified domain claims, users and agent key records. This is a staging data minimization policy, not a universal legal retention period. Existing ingest may independently delete old telemetry when receiving events.

Expiry cleanup is irreversible without backups. The systemd timer example is disabled until an administrator installs and enables it. Background jobs must be monitored for failure, storage pressure and clock drift.

## Security gaps before public accounts

- Replace SQLite with transactional PostgreSQL or a managed database, including migrations, tested backups, encryption and row-level/tenant access tests.
- Use a hardened, hosted identity provider or a thoroughly audited account stack with email verification, MFA, CSRF, secure sessions, lockout/abuse controls, recovery and deletion flows.
- Add centralized request limits, per-tenant quotas, audit trails and logging that excludes credentials and sensitive fields.
- Protect the public domain checker from SSRF using infrastructure-level egress restrictions.
- Place owner routes behind explicit HTTPS ingress and identity controls only after security review. Never reverse proxy the current prototype login publicly as-is.
- Verify deployment-specific Caddy syntax, DNS, TLS, firewall and SSH behavior on the target VPS. Static CI checks do not provide such evidence.

No live deployment is performed by this source package. Do not publish a deployment success claim until external checks run on the actual infrastructure.
