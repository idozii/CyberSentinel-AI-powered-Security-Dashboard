# CyberSentinel - Huong dan Buoc 18: Postgres Telemetry va Alerts

## 0. Dieu kien

- Buoc 17 da merge vao `main`, CI xanh va da tao backup Neon.
- Auth0 owner portal hoat dong tai `http://127.0.0.1:8007`.
- PostgreSQL role `cybersentinel_runtime` hoat dong; KHONG dung role owner cho app.
- Chua co public hosting. Buoc 18 chi thu nghiem tren localhost.

## 1. Tao branch va ap dung ZIP

Trong thu muc repository:

```bash
git status
git switch main
git pull --ff-only origin main
git switch -c feat/postgres-telemetry-alerts-step18
unzip -o ~/Downloads/CyberSentinel_Buoc_18_Postgres_Monitoring.zip -d .
source /home/idozii/envs/ds/bin/activate
python -m pip install -r requirements-owner.txt -r requirements-hosted.txt -r requirements-dashboard.txt
python -m pip install -e .
python -m unittest discover -s tests -v
python -m scripts.step18_preflight
python -m scripts.release_audit
```

The ZIP contains ONLY Step 18 changed/new files. Do not unzip if your local
Step 17 source is still dirty or not merged - inspect `git status` first.

## 2. Chay migration 002

**Backup project truoc khi thay doi Neon.** Dung connection string cua role
`cybersentinel_owner` va database `cybersentinel_stage` (direct endpoint) de
set `CYBERSENTINEL_PG_MIGRATION_DSN` trong terminal, khong dung runtime DSN.
Nhap bi mat trong Terminal, khong commit hoac gui cho nguoi khac:

```bash
printf 'Migration owner DSN: '
IFS= read -rs CYBERSENTINEL_PG_MIGRATION_DSN
printf '\n'
export CYBERSENTINEL_PG_MIGRATION_DSN
python -m scripts.step18_migrate
unset CYBERSENTINEL_PG_MIGRATION_DSN
```

Ky vong status `applied` hoac `already-applied`; neu checksum mismatch thi
DUNG, khong sua migration 001/002. Migration KHONG nhap/xoa SQLite.

## 3. Khoi dong portal va ingest trong hai terminal

Terminal A (cung cac bien Auth0 va `CYBERSENTINEL_PG_RUNTIME_DSN` cua Buoc 17):

```bash
source /home/idozii/envs/ds/bin/activate
uvicorn hosted_api.web:factory --factory --host 127.0.0.1 --port 8007 --workers 1
```

Terminal B (set RIENG runtime DSN, KHONG can Auth0 Client Secret):

```bash
source /home/idozii/envs/ds/bin/activate
printf 'Runtime DSN: '
IFS= read -rs CYBERSENTINEL_PG_RUNTIME_DSN
printf '\n'
export CYBERSENTINEL_PG_RUNTIME_DSN
uvicorn hosted_api.ingest:factory --factory --host 127.0.0.1 --port 8008 --workers 1
```

Open browser `http://127.0.0.1:8007/`. For a domain you control, add it
and verify the actual DNS TXT record first. Then choose **Manage monitoring**.
Create a key with a label and copy the token ONCE. In the same view, the domain
UUID in agent-friendly hex form is displayed.

## 4. Chay agent canh bao tren localhost

```bash
printf 'Agent key: '
IFS= read -rs CYBERSENTINEL_AGENT_KEY
printf '\n'
export CYBERSENTINEL_AGENT_KEY

python -m cybersentinel_agent.cli \
  --input simulations/runtime/logs/access.jsonl \
  --domain-id YOUR_VERIFIED_DOMAIN_HEX \
  --server http://127.0.0.1:8008
```

The log input MUST be a JSONL log matching the pre-existing agent adapter,
with events from the last five minutes. Adjust `--input` to the actual local
NGINX JSONL path; the example file is not guaranteed to exist. An existing
agent key from Step 11 (`csa_`) cannot access the new PostgreSQL store. Step 18
keys start `csp_`. Do not send a Step 18 key to the old SQLite endpoint.

Expected response includes `accepted`, `duplicates`, `alerts_updated`. Replay
identical `event_id` records within the same retention period to test dedup.
See alerts and acknowledge them from **Manage monitoring**. Do not copy secrets
into screenshots, logs or GitHub Issues.

## 5. CI va commit

```bash
python -m unittest discover -s tests -v
python -m scripts.step18_preflight
python -m scripts.step17_preflight
python -m scripts.release_audit
git diff --check
git status
```

The PostgreSQL integration tests intentionally **SKIP** in local unit suites
unless a disposable PostgreSQL test database is configured. The GitHub CI
`postgres-rls-staging` job runs them against PostgreSQL 17. Do not merge on a
skip-only local result: require the real PostgreSQL CI job to pass.

```bash
git add -A
git diff --cached --check
git diff --cached --stat
git commit -m "feat: add RLS-scoped PostgreSQL telemetry and alerts staging"
git push -u origin feat/postgres-telemetry-alerts-step18
```

Open PR against `main`, review changed files, check no `.env`, DSN, tokens,
passwords or private logs are staged. Wait for all CI jobs to pass before merge.

## 6. Rollback / known limits

Stop the `8008` process and revert Step 18 code via Git if needed. Leave the
Postgres 002 schema/data in place; dropping them requires a separate backup,
impact review and explicit approval. Existing SQLite agent pipeline unaffected.
No service is exposed on a public interface, and no production security claims.
