# CyberSentinel - Huong dan fast-track Buoc 26-30

Scope: local MVP rehearsal and limited-beta readiness checks. No public release is authorized.
Buoc 25 da merge vao main truoc khi ap dung. Khong can domain, Neon, Auth0 cho offline checks.

## 0. Apply patch

```bash
cd ~/Desktop/CyberSentinel-AI-powered-Security-Dashboard
git status
git switch main
git pull --ff-only origin main
git switch -c feat/beta-readiness-step26-30
unzip -o ~/Downloads/CyberSentinel_Buoc_26_30_Beta_Readiness.zip -d .
source /home/idozii/envs/ds/bin/activate
```

Do not change branch with uncommitted work. Inspect changed files before staging.

## 1. Buoc 26 - Container security rehearsal

The Docker Compose file does not publish ports and explicitly disables runtime
networking. It runs in-process smoke tests, not a hosted CyberSentinel instance.

```bash
python -m scripts.step26_30_preflight
docker compose -f deployment/step26/compose.smoke.yml up --build --abort-on-container-exit --exit-code-from smoke
docker compose -f deployment/step26/compose.smoke.yml down --remove-orphans
```

If Docker is unavailable, the Python preflight still checks basic static
boundaries; it does not prove that Docker builds successfully. This is a Linux
local rehearsal, NOT an Internet deployment blueprint. Check image dependency
CVEs and pin the image digest before any external exposure.

## 2. Buoc 27 - RLS tenant audit

Run without credentials first:

```bash
python -m scripts.step27_tenant_audit
```

Optional read-only verification using the already configured least-privilege
`CYBERSENTINEL_PG_RUNTIME_DSN`:

```bash
python -m scripts.step27_tenant_audit --live
```

Never use the owner/migration DSN. The script verifies the runtime role, five
RLS tables and a random unrecognized actor sees no rows, not real cross-tenant
performance. Two-owner integration tests remain in GitHub PostgreSQL 17 CI.
No mutation or schema changes are needed in Neon for Steps 26-30.

## 3. Buoc 28 - Local observability

Run the local demo in a terminal WITHOUT Neon/Auth0 secrets:

```bash
python -m scripts.step25_demo
```

Open `http://127.0.0.1:8019/demo/operations` or
`http://127.0.0.1:8019/demo/operations.json`.
These aggregate counters include accepted events, replay duplicates, rejected
credentials, invalid/stale events, key issuance and capacity rejections.
They are single-process, reset on restart, do not contain key/token, IP or
source references and cannot be used to infer production performance.

## 4. Buoc 29 - Reliability fault drills

```bash
python -m scripts.step29_reliability_drill
```

Expected `status: pass`, with checks for initial ingest, retry dedup, alert
uniqueness, invalid key/domain, stale/big input, key rotation, reset on restart.
This does NOT test PostgreSQL connection loss, process crashes under traffic,
durable agent outbox, or high-volume load. Those remain beta blockers.

## 5. Buoc 30 - Beta release checklist (always fail-closed)

```bash
python -m scripts.step30_beta_gate --expect-blocked
```

The command succeeds ONLY when the example evidence correctly blocks public
release. `python -m scripts.step30_beta_gate` intentionally exits 2. Do not
put secrets into `deployment/step30/beta_evidence.example.json`.
If you later create a private local evidence file, the checklist remains a
self-assessment; an all-true file never constitutes external approval.

## 6. Run all checks

```bash
python -m unittest discover -s tests -p test_step26_30_fasttrack.py -v
python -m scripts.step26_30_preflight
python -m scripts.step26_30_release
python -m unittest discover -s tests -v
python -m scripts.step21_quality_gate
python -m scripts.release_audit
python -m scripts.normalize_dashes --check
```

GitHub CI must pass Python 3.12/3.13 and PostgreSQL 17 RLS tests before merge.
Some local Postgres tests intentionally skip without an isolated test database.

## 7. Commit

```bash
git diff --check
git status
git add README.md .github/workflows/ci.yml .dockerignore \
  hosted_api/local_demo.py deployment/step26 deployment/step30 \
  scripts/step27_tenant_audit.py scripts/step29_reliability_drill.py \
  scripts/step30_beta_gate.py scripts/step26_30_preflight.py \
  scripts/step26_30_release.py tests/test_step26_30_fasttrack.py \
  docs/HUONG_DAN_BUOC_26_30.md docs/STEP26_30_SECURITY_BOUNDARIES.md \
  docs/BETA_GO_NO_GO.md
git diff --cached --check
git diff --cached --stat
git commit -m "feat: add fail-closed beta readiness and operational rehearsal steps 26-30"
git push -u origin feat/beta-readiness-step26-30
```

PR: https://github.com/idozii/CyberSentinel-AI-powered-Security-Dashboard/compare/main...feat/beta-readiness-step26-30?expand=1

Never add `.env`, connection strings, Auth0 Client Secret, unredacted logs,
real keys or local SQL exports. Review CI and merge only after green results.
