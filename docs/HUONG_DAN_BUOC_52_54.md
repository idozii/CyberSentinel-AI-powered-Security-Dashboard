# CyberSentinel - Steps 52-54 Fast Track

## Install after PR #36 has merged

Only 8 new source/test/documentation files are added by the archive, plus a
README. GitHub CI is patched by the installer, **not** replaced by an old copy.
The installer requires Step 49-51 checks in current workflow.

```bash
cd ~/Desktop/CyberSentinel-AI-powered-Security-Dashboard
git status
git switch main
git pull --ff-only origin main
git switch -c feat/step52-54-custody-cutover-readiness
unzip -o ~/Downloads/CyberSentinel_Steps52_54_FastTrack.zip -d .
source /home/idozii/envs/ds/bin/activate
python -m scripts.install_step52_54 --check-only
python -m scripts.install_step52_54
```

## Offline verification

```bash
python -m unittest discover -s tests -p test_step52_54_offline.py -v
python -m scripts.step54_readiness
python -m compileall -q scripts tests
python -m unittest discover -s tests -v
python -m scripts.normalize_dashes --check
git diff --check
```

`public_beta_allowed: false` and `decision: NO_GO` are the expected correct
outcomes. PostgreSQL tests will SKIP outside disposable GitHub Actions. A
SKIPPED test is not evidence of PostgreSQL success.

## Commit and PR

```bash
git add .github/workflows/ci.yml \
  scripts/step52_credential_custody.py scripts/step53_cutover_drill.py \
  scripts/step54_readiness.py scripts/install_step52_54.py \
  tests/test_step52_54_offline.py tests/test_step52_54_pg.py \
  docs/STEP52_54_SECURITY.md docs/HUONG_DAN_BUOC_52_54.md
git diff --cached --check
git commit -m "test: rehearse fail-closed tenant cutover and credential custody in CI"
git push -u origin feat/step52-54-custody-cutover-readiness
```

Create a PR to `main`, and require both Python versions, Docker, NGINX and
PostgreSQL jobs PASS. Specifically, the `Steps 52-54 disposable credential
custody and fail-closed rollback proof` step must PASS and not SKIP.

## Next development gate

Treat this as a CI security experiment. Before testing against real staging,
write an independently reviewed change plan for the actual Auth0 identity
broker and managed secret custody. A separate authorization is needed before
any modification to Neon, migrations, or staging connection roles.
