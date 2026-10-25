# CyberSentinel - Steps 42-43: fix CI and test database-bound tenant sessions

**Scope: CI-only proof of concept.** This package does not migrate the existing
`cs.*` tables, alter Neon staging or authorize Internet access. It is not a
public authentication or provisioning service.

## 1. Why this patch matters

After PR #32, the PostgreSQL RLS and OIDC foundation GitHub Actions job was
failing in Step 41 with:

```
AttributeError: 'Connection' object has no attribute 'executemany'
```

Psycopg 3 implements `executemany()` on Cursor, not Connection. Step 42
updates `scripts/step41_role_boundary.py` to open a cursor and write test
fixtures within the existing admin transaction.

A new `IsolatedTenantRepository` exercises session-bound tenant logins with
server-enforced RLS in a disposable PostgreSQL 17 service. It does not accept
caller-supplied `owner_id` or `cs.actor_id`; the tenant is taken from the
DB login role.

Step 43 adds a read-only architecture cutover checklist and explicit rollback
conditions. It intentionally does not apply schema or grants to Neon.

## 2. Install on the merged GitHub main branch

Ensure your working directory is clean, and save any changes first:

```bash
cd ~/Desktop/CyberSentinel-AI-powered-Security-Dashboard
git status
git switch main
git pull --ff-only origin main
git switch -c feat/step42-43-tenant-ci-repair
unzip -o ~/Downloads/CyberSentinel_Buoc_42_43_Tenant_CI_Repair.zip -d .
source /home/idozii/envs/ds/bin/activate
```

Only the exact 10 files listed in the archive are supplied. The archive
contains an updated `.github/workflows/ci.yml` based on the verified main
workflow, not an older reconstructed README. Review the diff before commit.

## 3. Offline checks

```bash
python -m unittest discover -s tests -p test_step42_43_offline.py -v
python -m scripts.step42_43_preflight
python -m scripts.step43_migration_plan
python -m scripts.step42_43_release
python -m unittest discover -s tests -v
python -m scripts.release_audit
python -m scripts.normalize_dashes --check
git diff --check
```

`public_beta: blocked` and `staging_migrated: false` are expected and correct.

## 4. GitHub Actions CI is the real PostgreSQL gate

The PostgreSQL 17 CI job must complete with **both** steps passing (not
skipped):

- `Step 41 independent login role tenant-isolation PostgreSQL proof`
- `Steps 42-43 role-scoped repository isolation PostgreSQL proof`

The remaining PostgreSQL/OIDC checks must also pass. Do not merge unless the
whole workflow is green. A local unittest skip is not a PostgreSQL pass.

## 5. Commit and PR

```bash
git status
git diff --stat
git diff --check
git add .github/workflows/ci.yml \
  scripts/step41_role_boundary.py \
  scripts/step42_isolated_repository.py \
  scripts/step43_migration_plan.py \
  scripts/step42_43_preflight.py scripts/step42_43_release.py \
  tests/test_step42_43_offline.py tests/test_step42_43_pg.py \
  docs/HUONG_DAN_BUOC_42_43.md docs/STEP42_43_SECURITY.md
git diff --cached --check
git commit -m "fix: restore PostgreSQL tenant CI and add role-bound adapter checks"
git push -u origin feat/step42-43-tenant-ci-repair
```

PR link:
https://github.com/idozii/CyberSentinel-AI-powered-Security-Dashboard/compare/main...feat/step42-43-tenant-ci-repair?expand=1

## 6. Next milestone

After successful CI, Step 44 should add an independently reviewed identity
broker and least-privilege tenant credential lifecycle on an *isolated*
non-production database, followed by staged migration and rollback drills.
Do **not** wire the PoC to your real Auth0 or Neon yet.
