# CyberSentinel - Buoc 16: PostgreSQL & Managed OIDC Identity Pilot

## Muc tieu

Step 16 proves an isolated PostgreSQL + verified OIDC access-token owner API in **private staging**. It does not replace the Step 10-15 SQLite service, provide browser login, or deploy public SaaS authentication. All new content uses ASCII `-` rather than Unicode dash characters.

## 16.1 Start from merged main

```bash
git status
git switch main
git pull --ff-only origin main
git switch -c feat/postgres-oidc-private-step16
unzip -o ~/Downloads/CyberSentinel_Buoc_16_Postgres_OIDC.zip -d .
source .venv/bin/activate
python -m pip install -r requirements-ml.txt -r requirements-dashboard.txt -r requirements-owner.txt -r requirements-hosted.txt
python -m pip install -e .
python -m unittest discover -s tests -v
python -m scripts.release_audit
python -m scripts.normalize_dashes --check
python -m scripts.step16_preflight
```

The complete repository previously had 200 tests in Step 15; this overlay adds 9 unit tests and 5 optional PostgreSQL integration tests (which **skip** if no test database is configured). The output should show roughly 214 total test cases, including 5 skipped in a no-Postgres local environment. The actual count is determined by `unittest` in your environment.

## 16.2 PostgreSQL test database - install locally or use the CI service

You need PostgreSQL 16+ and `psycopg[binary]`. The migration CLI requires a **separate privileged migration/admin DSN**. Create a non-superuser DB login called `cybersentinel_runtime` with a strong random password. It must not be a table owner or have BYPASSRLS. Create a fresh, isolated staging database using `createdb`, psql or your managed provider. Do not run this against a production database.

Example SQL to execute interactively with a privileged Postgres admin:

```sql
CREATE ROLE cybersentinel_runtime LOGIN PASSWORD 'REPLACE_WITH_STRONG_RANDOM_SECRET' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE DATABASE cybersentinel_stage;
```

Create the database with an admin role, not `cybersentinel_runtime`. The two SQL statements may need separate `psql` transactions. Grant connection to the application login when needed:

```sql
GRANT CONNECT ON DATABASE cybersentinel_stage TO cybersentinel_runtime;
```

Set secrets in a private environment or managed secret service (never commit `.env`). With a local staging PostgreSQL server:

```bash
read -rsp 'Migration PostgreSQL DSN: ' CYBERSENTINEL_PG_MIGRATION_DSN; echo
export CYBERSENTINEL_PG_MIGRATION_DSN
python -m scripts.step16_migrate
```

Repeat the migration command to verify it returns `already-applied`. Modifying the applied SQL file will trigger a checksum failure rather than silently rewriting the schema. This is migration 001, **not** a fully automated migration suite or SQLite data converter.

## 16.3 Configure a managed OIDC provider

Create a **staging API audience** in your OIDC provider, configure RS256-signed JWT access tokens and obtain issuer + JWKS HTTPS URL from its official provider configuration. The token must be issued for this API, not for a different application. Do not share access tokens in chat or screenshots.

```bash
export CYBERSENTINEL_OIDC_ISSUER='https://YOUR-ISSUER/'
export CYBERSENTINEL_OIDC_AUDIENCE='YOUR-API-AUDIENCE'
export CYBERSENTINEL_OIDC_JWKS_URL='https://YOUR-ISSUER/.well-known/jwks.json'
read -rsp 'Runtime PostgreSQL DSN: ' CYBERSENTINEL_PG_RUNTIME_DSN; echo
export CYBERSENTINEL_PG_RUNTIME_DSN
uvicorn hosted_api.main:create_app --factory --host 127.0.0.1 --port 8006
```

The `JWKS_URL` shown above is a placeholder: use the exact URL from your provider documentation, not a guessed path.

A separate terminal can check `http://127.0.0.1:8006/hosted/v1/health`. For authenticated endpoints, obtain a real OIDC access token from your configured provider and issue a request with the `Authorization: Bearer` header via a client that does not persist secrets in shell history.

New endpoints:

- `GET /hosted/v1/health` - private pilot status
- `GET /hosted/v1/me` - validated identity record (no email)
- `GET /hosted/v1/domains` - current identity's domain claims
- `POST /hosted/v1/domains` - issue DNS TXT challenge
- `POST /hosted/v1/domains/{id}/verify` - verify TXT claim

**No browser signup, public login, owner portal, remote ingest, or live alerts are migrated to this PostgreSQL service in Step 16.**

## 16.4 Staging tests and git workflow

`tests/test_step16_postgres.py` runs against a real PostgreSQL service only when `CYBERSENTINEL_TEST_PG_ADMIN_DSN` and `CYBERSENTINEL_TEST_PG_RUNTIME_DSN` are provided. The GitHub CI job provides these values using an ephemeral Postgres 17 service and a dedicated runtime user. Never use real staging credentials as CI test credentials.

```bash
git add hosted_api/ requirements-hosted.txt scripts/step16_migrate.py scripts/step16_preflight.py \
  tests/test_step16_hosted.py tests/test_step16_postgres.py \
  docs/HUONG_DAN_BUOC_16.md docs/STEP16_DATABASE_IDENTITY_SECURITY.md \
  .github/workflows/ci.yml scripts/release_audit.py README.md

git diff --cached --check
git diff --cached --stat
python -m scripts.release_audit
python -m scripts.normalize_dashes --check
git commit -m 'feat: add private PostgreSQL and OIDC identity pilot'
git push -u origin feat/postgres-oidc-private-step16
```

Create a PR against `main`. The CI must pass Python 3.12, 3.13, Docker localhost smoke, **and a separate real PostgreSQL RLS integration job** before merging.

## Step 17 preview

Design hosted account UX (authorization-code + PKCE using the IdP's client SDK), PostgreSQL-backed telemetry/alerts and migration strategy, verified-domain renewal, and security controls before any public signup. Only after that should we expose the hosted owner dashboard via HTTPS. Do not open port 8006 publicly.
