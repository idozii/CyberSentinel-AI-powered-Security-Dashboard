# CyberSentinel - Final Portfolio Handoff

## This patch

- Adds a source/evidence final gate that reuses the existing public-metrics schema and reconciles holdout detection numbers.
- Writes a deterministic, offline recruiter handoff to a **new directory outside Git**.
- Adds idempotent, narrowly scoped installer entries into README and existing CI.
- Keeps Neon/Auth0/hosted apps/SQLite/SQL migrations untouched.
- Does **not** fabricate screenshots, videos, research experiments, or claim SaaS beta is approved.

## Install

```bash
python -m scripts.install_portfolio_finalizer --check-only
python -m scripts.install_portfolio_finalizer
python -m unittest discover -s tests -p test_portfolio_finalizer.py -v
python -m scripts.portfolio_finalizer
python -m scripts.portfolio_finalizer --output-dir /tmp/cybersentinel-recruiter-HANDOFF
```

The output directory must not exist. All exported files are source evidence and interview guides, not trained models or user records. To generate a standalone HTML report as well, use `python -m scripts.zero_cost_portfolio audit --output /tmp/cybersentinel-evidence-UNIQUE.html` with a new name.

## Do the human part

Use [Portfolio 100% Acceptance](PORTFOLIO_100_ACCEPTANCE.md) to capture actual screenshots, video, clean-machine proof, link verification, team attribution and release evidence. These are the remaining actions that code cannot honestly certify.

## Example release title

`CyberSentinel - Cloud-Free Security Telemetry Research Portfolio`

Suggested GitHub release description: reproducible synthetic telemetry pipeline, offline dashboard, recorded Isolation Forest recall 29.17% on 24 attack windows, explicit research limitations, green CI, no cloud requirement. Never claim production IDS or verified real attack detection.
