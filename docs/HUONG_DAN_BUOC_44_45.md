# CyberSentinel - Steps 44-45 patch application guide

This patch targets GitHub `main` after merged PR #33 (`06439f9`). It only supplies new source, tests, documentation and an additive workflow installer. It does not contain passwords or touch Neon.

## Apply on Ubuntu

```bash
cd ~/Desktop/CyberSentinel-AI-powered-Security-Dashboard
git status
git switch main
git pull --ff-only origin main
git switch -c feat/step44-45-disposable-security-drills
unzip -o ~/Downloads/CyberSentinel_Steps44_45_Patch.zip -d .
source /home/idozii/envs/ds/bin/activate
python -m scripts.install_step44_45
python -m scripts.install_step44_45 --check
```

Do not run if there are uncommitted changes that you need to preserve; commit or stash them first. `install_step44_45` refuses an unexpected CI layout and is idempotent. Review `.github/workflows/ci.yml` before committing.

## Offline validation

```bash
python -m compileall -q scripts/step44_tenant_lifecycle.py scripts/step45_security_gate.py scripts/install_step44_45.py tests/test_step44_45_offline.py tests/test_step44_45_pg.py
python -m unittest discover -s tests -p test_step44_45_offline.py -v
python -m scripts.step45_security_gate
python -m unittest discover -s tests -v
python -m scripts.normalize_dashes --check
git diff --check
```

The offline gate should say `ready_for_ci_review`, `public_beta_allowed: false`, and `staging_migrated: false`. These outputs do not claim PostgreSQL integration success.

## PostgreSQL integration tests

Do not run the role lifecycle test against a user-owned database. The PG tests run only in the existing GitHub Actions disposable PostgreSQL 17 job, guarded by `CYBERSENTINEL_ISOLATED_PG_CI=1` and the exact Step 41 admin DSN requirements. GitHub Actions must show the **Steps 44-45 disposable role lifecycle PostgreSQL proof** step as **PASS**, never SKIPPED.

## Review and push

```bash
git status
git diff -- .github/workflows/ci.yml
git add .github/workflows/ci.yml scripts/step44_tenant_lifecycle.py scripts/step45_security_gate.py scripts/install_step44_45.py tests/test_step44_45_offline.py tests/test_step44_45_pg.py docs/STEP44_45_SECURITY.md docs/HUONG_DAN_BUOC_44_45.md
git diff --cached --check
git commit -m "test: rehearse disposable tenant credential lifecycle and release gates"
git push -u origin feat/step44-45-disposable-security-drills
```

Open a PR into `main`. Never merge until the whole workflow passes. On failure, inspect the specific PostgreSQL job log, keep the branch open, and correct the test or implementation. This patch intentionally does not create migrations or deployment steps.
