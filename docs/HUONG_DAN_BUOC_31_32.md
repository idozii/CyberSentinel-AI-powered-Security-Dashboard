# CyberSentinel - Step 31-32 SOC UI v2 and beta preparation

## What changed

- Step 31: responsive, standalone Security Operations Center (SOC) dashboard UI using local first-party CSS and JavaScript. The overview includes computed KPI cards, a 12-minute event histogram, HTTP status distribution, recent alerts, recent events, and an agent key panel.
- Step 32: read-only Beta Readiness page using the existing Step 30 fail-closed checklist, plus regression tests and offline release preflight.
- Evaluation, threshold tuning, alert triage, operations, key rotation and CSRF protections remain in place.
- No CDN, frontend build chain, database migrations, domain, Auth0, Neon, or production telemetry needed.
- The dashboard has NOT been made public. No beta acceptance conditions are marked complete.

## Apply

From your local repo, after confirming a clean `git status`:

```bash
cd ~/Desktop/CyberSentinel-AI-powered-Security-Dashboard
git switch main
git pull --ff-only origin main
git switch -c feat/soc-dashboard-v2-step31-32
unzip -o ~/Downloads/CyberSentinel_Buoc_31_32_SOC_Dashboard.zip -d .
source /home/idozii/envs/ds/bin/activate
```

## Verify

```bash
python -m unittest discover -s tests -p test_step31_32_soc_ui.py -v
python -m scripts.step31_32_preflight
python -m scripts.step31_32_release
python -m unittest discover -s tests -v
python -m scripts.step21_quality_gate
python -m scripts.step26_30_release
python -m scripts.release_audit
python -m scripts.normalize_dashes --check
```

## Run locally

```bash
python -m scripts.step25_demo
```

Open `http://127.0.0.1:8019/`.

- Overview: `/`
- Alert triage: `/demo/alerts`
- Synthetic evaluation: `/demo/evaluation`
- Tuning lab: `/demo/tuning`
- Operations: `/demo/operations`
- Beta readiness: `/demo/readiness` (expected NO-GO)

Generate a new local demo key, send synthetic NGINX events through the demo agent, and refresh the overview. Counters and charts represent only current ephemeral demo records. No test samples are silently inserted.

If an older server is occupying port 8019, stop it and restart using the code from this branch. In the browser use Ctrl+Shift+R after updating static assets.

## GitHub PR

```bash
git diff --check
git add README.md .github/workflows/ci.yml \
  hosted_api/local_demo.py hosted_api/soc_ui.py hosted_api/assets/soc.css \
  hosted_api/assets/soc.js scripts/step31_32_preflight.py \
  scripts/step31_32_release.py tests/test_step31_32_soc_ui.py \
  docs/HUONG_DAN_BUOC_31_32.md docs/STEP31_32_SECURITY.md
git diff --cached --check
git diff --cached --stat
git commit -m "feat: redesign localhost SOC dashboard and expose fail-closed beta readiness"
git push -u origin feat/soc-dashboard-v2-step31-32
```

Create one PR targeting `main`. Require GitHub CI success before merge. Keep the previous `local-mvp-v1.0.0` tag unchanged; this is a new unreleased change set.

## Next milestone beyond Step 32

A public multi-tenant service requires a controlled domain, TLS termination and authorized beta traffic; durable agent queue and recovery; RLS boundary review; monitored backup/restore; privacy/legal review; independent security testing; and an operational incident response plan. See `docs/BETA_GO_NO_GO.md`. Local UI work does not satisfy these conditions.
