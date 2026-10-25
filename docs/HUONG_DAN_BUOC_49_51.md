# CyberSentinel - Huong dan Steps 49-51 Fast Track

Scope: ONLY local/offline unit testing and disposable PostgreSQL 17 in GitHub
Actions CI. No domain purchase, no staging Neon or Auth0 changes.

## 1. Prepare a clean feature branch

```bash
cd ~/Desktop/CyberSentinel-AI-powered-Security-Dashboard
git status
git switch main
git pull --ff-only origin main
git switch -c feat/step49-51-tenant-broker-canary
unzip -o ~/Downloads/CyberSentinel_Steps49_51_FastTrack.zip -d .
source /home/idozii/envs/ds/bin/activate
```

The ZIP contains only 8 new source/test/doc files plus `README.txt`.
It does not overwrite existing migrations, application source or CI workflow.

## 2. Register CI tests safely

```bash
python -m scripts.install_step49_51 --check-only
python -m scripts.install_step49_51
```

Installer checks for the previously merged Step 46-48 job and inserts the
new offline and isolated PostgreSQL jobs before stable CI anchors.

## 3. Run local validation

```bash
python -m unittest discover -s tests -p test_step49_51_offline.py -v
python -m scripts.step51_release_gate
python -m compileall -q scripts tests
python -m unittest discover -s tests -v
python -m scripts.normalize_dashes --check
git diff --check
```

All PostgreSQL tests in `test_step49_51_pg.py` intentionally SKIP outside
an explicitly guarded GitHub Actions PostgreSQL 17 service; this is not a PASS.

## 4. Commit / push / Pull Request

```bash
git add .github/workflows/ci.yml \
  scripts/step49_credential_broker.py \
  scripts/step51_application_canary.py \
  scripts/step51_release_gate.py \
  scripts/install_step49_51.py \
  tests/test_step49_51_offline.py \
  tests/test_step49_51_pg.py \
  docs/STEP49_51_SECURITY.md \
  docs/HUONG_DAN_BUOC_49_51.md

git diff --cached --check
git commit -m "test: validate tenant credential broker and revocation canary in isolated CI"
git push -u origin feat/step49-51-tenant-broker-canary
```

Create the PR from branch `feat/step49-51-tenant-broker-canary` to `main`.
Review GitHub Actions job "PostgreSQL RLS and OIDC foundation" and ensure
"Steps 49-51 isolated credential broker, revoke and canary PostgreSQL proof"
actually runs and PASSES. Do not merge before complete CI passes.

## 5. Security no-go

An offline success reports `ready_for_ci` and `public_beta_allowed: false`.
This is intentional. The synthetic verifier is not integrated with real OIDC.
`HostedStore` and `MonitoringStore` are not migrated; do not enable public
multi-tenant website monitoring based on this CI exercise.
