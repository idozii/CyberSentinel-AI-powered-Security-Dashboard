# CyberSentinel - Zero-Cost Portfolio Release

**Milestone:** a fresh checkout has an offline-first research showcase without Neon, Auth0, Docker, managed storage, or live telemetry. The published showcase remains a transparent synthetic experiment, not a live IDS.

## Architecture and financial boundaries

| Use case | Stack | External recurring expense required |
|---|---|---|
| Public research/portfolio page | Bundled `dashboard/public_metrics.json` + `dashboard/public_app.py` | No DB/Auth0 expense; optional Streamlit Community Cloud free deployment subject to provider limits |
| Local browser demo | `python -m scripts.zero_cost_portfolio demo` | None beyond the operator's machine and electricity |
| Local source evidence and downloadable report | `python -m scripts.zero_cost_portfolio audit --output ...` | None |
| Synthetic ingest + alerting demo | Step 25 FastAPI TestClient in-process (`audit --full`) | None; no Docker/Neon/Auth0 needed |
| Full reproducible traffic/ML pipeline | Local Docker, Python and scikit-learn | None beyond local compute |
| Optional private owner system | Existing SQLite-only localhost service | None beyond local compute |
| Multi-user public SaaS | **Not delivered.** Needs reviewed identity/DB architecture, deployment, operations, privacy, security review. | Not demonstrated within zero cost |

Running the static showcase with `demo` does not load or connect to Neon/Postgres/Auth0. The command removes known credentials from the Streamlit subprocess environment, binds to `127.0.0.1`, disables Streamlit telemetry collection and disables the outbound HTTPS website checker through `CYBERSENTINEL_OFFLINE_ONLY=1`. These are **application safeguards**, not a network sandbox: clicking external documentation links or third-party library behavior may still use the internet. For a strict network-isolated demonstration, disconnect networking or use a real OS/container egress policy.

## Install and verify

Python 3.12 or 3.13 recommended. In the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-ml.txt -r requirements-dashboard.txt -r requirements-owner.txt
python -m pip install -e .
python -m scripts.zero_cost_portfolio audit
python -m scripts.zero_cost_portfolio audit --full
python -m unittest discover -s tests -p test_zero_cost_portfolio.py -v
```

`audit` uses only the standard library and `dashboard.public_data`. `audit --full` runs the existing Step 25 in-process local demo and needs project dependencies. Both produce JSON to stdout. `audit` deliberately preserves the warning that the Isolation Forest failed to detect the recorded path-scanning holdout windows.

### Start the standalone research dashboard

```bash
python -m scripts.zero_cost_portfolio demo
# Open http://127.0.0.1:8501
# Ctrl+C to end the process
```

No PostgreSQL, Auth0 account, `.env`, domain registration, API server or local data generation is required. The dashboard reads the **committed synthetic aggregate evidence**. This is not real-time threat monitoring. Run the local full research explorer separately with the original instructions in `README.md` if you have generated Docker-lab data.

### Generate a self-contained HTML/JSON evidence report

```bash
python -m scripts.zero_cost_portfolio audit --output /tmp/cybersentinel_evidence.html
python -m scripts.zero_cost_portfolio audit --full --output /tmp/cybersentinel_full_audit.json
```

An output file must be **new**, must use `.html` or `.json`, and must be outside the repository. The tool will not overwrite an existing file. The HTML report contains no remote CSS, JavaScript or data fetches. The report is a summary of stored research evidence, *not newly computed evaluation metrics*.

## GitHub / public deployment

- The only suitable always-public experience at this stage is the preexisting Streamlit showcase: entrypoint `dashboard/public_app.py` with available bundled metrics. Its passive website checker remains available on the **public** version, subject to current checks and provider resources. The localhost `demo` command explicitly disables it.
- Streamlit Community Cloud can host the showcase without PostgreSQL or Auth0; free access, policy and resource limits can change. Do not put any API keys or `.env` into Streamlit secrets for the static showcase.
- GitHub Actions continues to test existing PostgreSQL on its **disposable service**; those tests are not dependent on a paid Neon account.
- Do not expose `owner_api`, the local Auth0 staging pilot, the CI-only tenant-bound HTTP API, or the SQLite owner database to the public.

## Acceptance criteria

1. Installer is idempotent; `git diff` shows only README, public demo guard and CI plus new files.
2. `python -m scripts.zero_cost_portfolio audit` returns `status: pass` on intact bundled data.
3. `python -m scripts.zero_cost_portfolio audit --full` passes the Step 25 synthetic in-process API smoke.
4. Local portfolio dashboard opens on `127.0.0.1:8501` with no Neon or Auth0 configured.
5. Website checker is absent from the offline navigation and the Overview shortcut is disabled.
6. Invalid evidence, changed source anchors and malformed output requests fail closed.
7. GitHub Actions Python 3.12/3.13, PostgreSQL, Docker and smoke jobs all pass after the PR.
8. `public_multi_tenant_beta_allowed` and `production_saas_ready` remain `false`.

## Threat model and limitations

The static report contains only aggregated synthetic lab results. It must not be mistaken for monitoring of user domains. The Streamlit process is not hardened as a multi-user tenant service; the public website checker is separately bounded but is not proven safe under unbounded adversarial scale. Machine compromise, browser links, third-party package behavior, local host networking, paid tiers and account-specific free plans are outside this release's guarantees. The existing shared `cybersentinel_runtime` / mutable `cs.actor_id` problem remains on the optional hosted staging path. **No public multi-tenant beta approval.**
