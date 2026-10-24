# CyberSentinel - Step 25 Local Portfolio MVP Release

Release scope: an isolated, non-persistent, non-public cybersecurity detection playground.
No real-user telemetry and no public SaaS service are included.

## One-command start

From repository root, with Python environment active and dependencies installed:

```bash
python -m scripts.step25_demo
```

This launches the UI on `http://127.0.0.1:8019/` using only loopback. Do not expose it through cloud proxy, Caddy or SSH forwarded public listener. Stop with Ctrl+C; this clears the demo state.

## Reviewer walkthrough

1. Open dashboard and generate a `csd_` local key; save it privately.
2. Generate five synthetic login 401 NGINX lines (`scripts.step19_generate_logs`).
3. Run `cybersentinel-demo-agent` in dry-run mode first, then submit with Demo Domain ID.
4. Observe one login-failures alert, triage by high severity, inspect aggregated evidence.
5. Retry exact file and observe `accepted=0` with duplicates; acknowledge alert.
6. Generate a different file for another synthetic scenario and review resulting alerts.
7. Open Step 20 evaluation and Step 21 tuning to demonstrate limitations and overfitting.
8. Run `python -m scripts.step24_failure_analysis` for 11 additional robustness cases.
9. Run `python -m scripts.step25_release`; every check must be true.
10. Rotate key, verify old key rejection and cleared state. Stop demo process.

## Acceptance checklist

- Combined unit tests PASS; local skips clearly documented.
- `scripts.step21_quality_gate`, `scripts.step25_preflight`, `scripts.step25_release` PASS.
- GitHub CI Python 3.12/3.13, lab smoke, PostgreSQL 17 RLS integration PASS on PR.
- No untracked DSN, tokens, private logs, `.env` files or generated report committed.
- Screenshot and README describe this explicitly as localhost/synthetic, not production-ready.

## Rollback and support

No database migration. Stop the demo and revert the fast-track source commit if needed. Starting a new demo process discards prior in-memory data. If a port is in use, stop the previous local listener rather than binding `0.0.0.0`. If user no longer has a key, generate a new one and recreate synthetic data. If generated logs are over 5 minutes old, generate a fresh file with a new filename.

## Future work

Production/beta still require a real controlled domain, tenant security review, persistent telemetry, agent lifecycle monitoring, durable buffering for Postgres ingest, operational observability, secure deployment, privacy/compliance and external review. See `docs/ROADMAP_TO_PRODUCT.md`.
