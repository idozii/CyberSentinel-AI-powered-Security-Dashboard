# CyberSentinel - Buoc 39-40: Security Boundary & Limited Beta Preparation

Release scope: **LOCAL / disposable CI only**. This patch does not change Neon, deploy a server, operate public HTTPS, or fix multi-tenant database privilege separation. Do NOT put credentials into source control.

## 1. Apply the patch

```bash
cd ~/Desktop/CyberSentinel-AI-powered-Security-Dashboard
git status
git switch main
git pull --ff-only origin main
git switch -c feat/actor-boundary-beta-gate-step39-40
unzip -o ~/Downloads/CyberSentinel_Buoc_39_40_Beta_Security.zip -d .
python -m scripts.install_step39_40
source /home/idozii/envs/ds/bin/activate
```

The installer appends a README section and CI jobs without overwriting existing application code. It is safe to invoke twice. Inspect `git diff` afterward.

## 2. Step 39: Review a shared runtime credential compromise

The existing runtime login `cybersentinel_runtime` sets custom transaction-local `cs.actor_id` in `hosted_api/postgres.py`. It has RLS for the five `cs` tables and normal API tests verify owner separation. But a party with **direct SQL access using that same runtime login** can change their session-local `cs.actor_id`. That is NOT a proof of identity under credential compromise.

Run static, offline inspection:

```bash
python -m scripts.step39_actor_boundary
```

Expected `status: pass`, **finding: shared_runtime_role_mutable_actor_id**, `public_beta_allowed: false`. `pass` means the audit correctly detects the issue, **NOT that the risk is fixed**.

The disposable PostgreSQL 17 CI test `tests/test_step39_actor_spoof_pg.py` independently demonstrates the issue with synthetic owners. It is guarded by localhost-only `CYBERSENTINEL_TEST_PG_*` DSNs; never run it against Neon or your live database. GitHub CI owns a disposable local PostgreSQL service for the test.

## 3. Step 40: Offline beta readiness and restore runbook

```bash
python -m scripts.step40_readiness_report
python -m scripts.step40_readiness_report --output /tmp/cybersentinel-step40-readiness.json
python -m scripts.step39_40_preflight
python -m scripts.step39_40_release
```

`/tmp/cybersentinel-step40-readiness.json` must not already exist (create-only, private mode 0600). This is a **report**, not an external security approval. The beta gate is intentionally BLOCKED. For disaster-recovery and HTTPS design, read `docs/STEP40_RESTORE_HTTPS_RUNBOOK.md`. No real backup, restore, TLS or domain validation occurs in these Python scripts.

## 4. Full tests

```bash
python -m unittest discover -s tests -p test_step39_40_safety.py -v
python -m unittest discover -s tests -v
python -m scripts.step39_40_preflight
python -m scripts.step39_40_release
python -m scripts.release_audit
python -m scripts.normalize_dashes --check
```

Some PostgreSQL tests skip without the isolated test database. The dedicated PostgreSQL CI job must PASS. Do not treat a local skip as a success of those integration checks.

## 5. Commit & PR

```bash
git diff --check
git status
git add README.md .github/workflows/ci.yml \
  scripts/install_step39_40.py scripts/step39_actor_boundary.py \
  scripts/step40_readiness_report.py scripts/step39_40_preflight.py \
  scripts/step39_40_release.py tests/test_step39_actor_spoof_pg.py \
  tests/test_step39_40_safety.py docs/HUONG_DAN_BUOC_39_40.md \
  docs/STEP39_40_SECURITY.md docs/STEP40_RESTORE_HTTPS_RUNBOOK.md
git diff --cached --check
git diff --cached --stat
git commit -m "test: document compromised runtime tenant boundary and gate beta release"
git push -u origin feat/actor-boundary-beta-gate-step39-40
```

Open: https://github.com/idozii/CyberSentinel-AI-powered-Security-Dashboard/compare/main...feat/actor-boundary-beta-gate-step39-40?expand=1

Only merge when CI passes (Python 3.12/3.13, PostgreSQL 17, local smoke, Docker smoke). The `local-mvp-v1.0.0` tag stays immutable.

## 6. After merging

**Do not publish SaaS or mark Step 39 as security resolved.** Next engineering milestone: redesign database authorization so a compromised runtime credential cannot select an arbitrary owner, add adversarial tests expecting impersonation to FAIL, then test actual deployment backup/restore and HTTPS under authorized infrastructure. This requires an architecture/security review before traffic exposure.
