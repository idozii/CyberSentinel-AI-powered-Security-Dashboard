# CyberSentinel - Steps 58-63 in one PR

## 1. Prerequisites

- Baseline main includes merged PR #38 (commit `5d73c6d` or newer).
- Clean working tree. Save local work first.
- No production or Neon credentials. This patch only targets disposable GitHub Actions PostgreSQL 17.

## 2. Apply patch on Ubuntu

```bash
cd ~/Desktop/CyberSentinel-AI-powered-Security-Dashboard
git status
git switch main
git pull --ff-only origin main
git switch -c feat/step58-63-http-vertical-slice
unzip -o ~/Downloads/CyberSentinel_Steps58_63_OnePR.zip -d .
source /home/idozii/envs/ds/bin/activate
python -m scripts.install_step58_63 --check-only
python -m scripts.install_step58_63
```

The package does not overwrite `.github/workflows/ci.yml`; installer verifies exact anchors and inserts only two explicit test stages. It is idempotent. Review the diff before committing.

## 3. Offline checks

```bash
python -m unittest discover -s tests -p test_step58_63_offline.py -v
python -m scripts.step63_security_gate
python -m compileall -q scripts tests hosted_api
python -m unittest discover -s tests -v
python -m scripts.normalize_dashes --check
git diff --check
```

`decision: NO_GO` and `public_beta_allowed: false` are correct. Real PostgreSQL tests must run **not skipped** in GitHub CI.

## 4. Git and PR

```bash
git add hosted_api/disposable_tenant_http.py \
  scripts/install_step58_63.py scripts/step63_security_gate.py \
  tests/test_step58_63_offline.py tests/test_step58_63_pg.py \
  docs/STEP58_63_ARCHITECTURE.md docs/HUONG_DAN_BUOC_58_63.md \
  .github/workflows/ci.yml
git diff --cached --check
git commit -m "test: integrate signed OIDC with isolated tenant HTTP and PostgreSQL RLS"
git push -u origin feat/step58-63-http-vertical-slice
```

Open PR to `main`. Merge only after all Python, PostgreSQL, Docker and NGINX checks pass. Explicitly inspect `Steps 58-63 signed OIDC to HTTP to PostgreSQL tenant boundary` in the PostgreSQL job: PASS, **not SKIPPED**.

## 5. Next milestone

Do not do another sequence of synthetic-only prototypes. The next deliverable should be an independently reviewed architecture/design approval for real managed-secret custody and provisioning, followed by an **authorized private staging deployment** on a separate environment with migration, backup, realistic load, monitoring and rollback. This work requires explicit owner sign-off and must not be inferred from green CI.
