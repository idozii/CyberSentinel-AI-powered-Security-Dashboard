# CyberSentinel - Steps 55-57 Fast Track

**Scope: CI-only tenant access boundary, five-table canary and architecture gate.** Never run against Neon/production or a database holding genuine tenant data.

## 1. Setup

```bash
cd ~/Desktop/CyberSentinel-AI-powered-Security-Dashboard
git status
git switch main
git pull --ff-only origin main
git switch -c feat/step55-57-tenant-admission
unzip -o ~/Downloads/CyberSentinel_Steps55_57_FastTrack.zip -d .
source /home/idozii/envs/ds/bin/activate
```

If Git has local changes, save or commit them first. Review `git diff` before staging.

## 2. Install CI steps

```bash
python -m scripts.install_step55_57 --check-only
python -m scripts.install_step55_57
```

This installer requires the exact existing workflow anchors and Steps 52-54, and refuses partial or unexpected changes.

## 3. Offline verification

```bash
python -m unittest discover -s tests -p test_step55_57_offline.py -v
python -m scripts.step57_architecture_gate
python -m compileall -q hosted_api scripts tests
python -m unittest discover -s tests -v
python -m scripts.normalize_dashes --check
git diff --check
```

The `NO_GO` result and `public_beta_allowed: false` are expected. Local PostgreSQL tests are SKIPPED without the exact disposable GitHub CI guard; a SKIP is not a pass.

## 4. Commit, push, PR

```bash
git add .github/workflows/ci.yml \
  hosted_api/tenant_session_boundary.py \
  scripts/step56_boundary_canary.py scripts/step57_architecture_gate.py \
  scripts/install_step55_57.py \
  tests/test_step55_57_offline.py tests/test_step55_57_pg.py \
  docs/STEP55_57_ARCHITECTURE.md docs/HUONG_DAN_BUOC_55_57.md
git diff --cached --check
git commit -m "test: enforce disposable tenant admission and role-bound canary"
git push -u origin feat/step55-57-tenant-admission
```

Create a PR to `main` and verify the dedicated **Steps 55-57 tenant session admission and isolation PostgreSQL proof** job actually executes, not SKIPPED. All Python, NGINX, Docker, PostgreSQL and OIDC checks must pass before merge.

## 5. What comes next

Steps 58-60 should stop expanding synthetic proofs and focus on a reviewed *real* application integration plan: choose a credential manager, run an independently reviewed Auth0 identity trust architecture, implement per-tenant pool lifecycle, and rehearse a controlled staging migration only after authorization. Do not modify existing Neon staging without a separate approved plan.
