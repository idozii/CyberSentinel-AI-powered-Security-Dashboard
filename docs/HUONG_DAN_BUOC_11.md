# CyberSentinel - Buoc 11: Local NGINX Agent and Secure Ingestion

## Scope

Step 11 extends the Step 10 *local-only* owner portal. A DNS-verified domain owner can provision a scoped agent key, send a bounded batch of sanitized NGINX JSON access log entries to the Owner API, inspect recent events, and revoke the key. Data is saved in the existing ignored SQLite database.

**This is not a remote 24/7 monitoring service or a production IDS.** No automatic alerts, continuous log tailing, hosted owner accounts, or public ingest endpoints are delivered by Step 11. The Step 12 detector will need live-window feature engineering without `simulation_run_id`, a tested detection strategy, alert management and retention rules.

## Architecture

```
Owner logs in -> DNS-verifies domain -> issues agent key (visible once)
       |
Local NGINX JSONL file -> cybersentinel-agent -> MINIMAL event schema
       |                              (no raw IP, URL/query, body or headers)
       +---- POST localhost:8002/agent/v1/ingest (bearer agent key)
                     |
             owner_api telemetry service
                     |
             OwnerStore SQLite, domain-scoped foreign keys
                     |
             GET /owner/domains/{domain_id}/telemetry (owner bearer session)
                     |
             Local owner_portal/app.py
```

Design boundaries:

- Key issuance requires a Step 10 DNS-verified domain and its owner session. API keys are random and stored as SHA-256 digests; plaintext is returned **only on creation**.
- A key can ingest only for its verified domain. Owner reads require their own session. Revoked keys, unverified claims and cross-tenant reads are rejected.
- Only 25 events per request and 32 KiB JSON request bodies. A domain accepts at most 300 new/requested events per rolling minute in this local prototype. Events more than 5 minutes old or in the future are rejected. Retention cleanup is triggered on ingestion for events older than 7 days.
- Input schema rejects unknown keys. NGINX raw IP is replaced with an HMAC pseudonym keyed by agent key and UTC day; raw IP, query strings, paths, headers, cookies, user agents, passwords, bodies and stack traces are never sent.
- Replaying the same event ID to the same domain is idempotent. Local agent accepts only `http://127.0.0.1:8002`, disables proxy environment variables, and does not follow redirects.

## 11.1 Update local Git repo

From the CyberSentinel repository root:

```bash
 git status
 git switch main
 git pull --ff-only origin main
 git switch -c feat/local-agent-ingestion-step11
 unzip -o ~/Downloads/CyberSentinel_Buoc_11_Agent_Ingestion.zip -d .
```

Don't switch branches with uncommitted work unless you have preserved it.

## 11.2 Apply ASCII hyphen normalization (requested convention)

The user requested no Unicode em/en dashes in the files. The tool normalizes **only tracked UTF-8 text**, including Markdown, Python and YAML. It does not touch binary files, ignored runtime logs, secrets or ASCII double hyphens used in CLI flags.

Stage the new files so the normalizer recognizes them:

```bash
 git add owner_api/main.py owner_api/telemetry.py owner_portal/app.py \
   cybersentinel_agent/ pyproject.toml scripts/normalize_dashes.py \
   tests/test_step11_agent.py docs/HUONG_DAN_BUOC_11.md docs/OWNER_AGENT_SECURITY.md \
   .github/workflows/ci.yml scripts/release_audit.py
 python -m scripts.normalize_dashes --apply
 python -m scripts.normalize_dashes --check
```

`--apply` may modify many existing `README.md`, `docs/*.md` and some Python strings. This is intentional. **Do not replace ASCII `--` globally**: it is required by flags such as `--host`, `--input`, and code/CI syntax. Use `git diff` to review all changes.

## 11.3 Install and test

```bash
source .venv/bin/activate
python -m pip install -r requirements-ml.txt -r requirements-dashboard.txt -r requirements-owner.txt
python -m pip install -e .
python -m unittest discover -s tests -v
python -m scripts.release_audit
```

Expected for the full repository: 115 Step 10 tests + 18 Step 11 tests = **133 tests**. Python 3.11 or newer is supported by the local package; GitHub CI verifies Python 3.12 and 3.13. If tests fail, do not commit or merge.

## 11.4 Start Owner API and Portal

Terminal 1:

```bash
source .venv/bin/activate
uvicorn owner_api.main:app --host 127.0.0.1 --port 8002
```

Terminal 2:

```bash
source .venv/bin/activate
streamlit run owner_portal/app.py --server.address 127.0.0.1 --server.port 8503
```

Open `http://127.0.0.1:8503`. Log into your **local** account. Only DNS-verified domains can issue agent keys. Click **Generate agent API key**, then copy its value. Do not paste the key into ChatGPT, screenshots, or GitHub. Store it only in a local environment variable. Example:

```bash
read -rsp 'Paste your agent key: ' CYBERSENTINEL_AGENT_KEY; echo
export CYBERSENTINEL_AGENT_KEY
```

The owner domain ID is displayed in the portal's generated command or via `GET /owner/domains` using an authenticated owner session.

## 11.5 Local smoke test with three synthetic requests

This creates a fresh JSONL file, with a documentation IP. No real web traffic or users are involved:

```bash
python - <<'PY'
import json, datetime
from pathlib import Path
now = datetime.datetime.now(datetime.timezone.utc).isoformat()
root = Path('simulations/runtime/owner')
root.mkdir(parents=True, exist_ok=True)
path = root / 'step11_demo_nginx.jsonl'
with path.open('w', encoding='utf-8') as handle:
    for idx, (uri, status) in enumerate([('/', 200), ('/login', 401), ('/admin', 404)]):
        event = {'time_iso8601': now, 'remote_addr': '192.0.2.10',
                 'request_method': 'GET', 'uri': uri, 'status': str(status),
                 'request_time': '0.012', 'request_length': '120',
                 'bytes_sent': '250', 'request_id': f'csdemo2026{idx:022d}'}
        handle.write(json.dumps(event) + '\n')
print('Sample log:', path)
PY
```

Then provide the domain ID of a **verified** domain in your own local Owner Portal:

```bash
cybersentinel-agent \
  --input simulations/runtime/owner/step11_demo_nginx.jsonl \
  --domain-id REPLACE_WITH_YOUR_VERIFIED_DOMAIN_ID
```

Expected output is `submitted: 3`, `accepted: 3`, `duplicates: 0`; repeating the command should return `duplicates: 3` (if timestamps remain within five minutes). Refresh the verified domain in the Owner Portal to see three events and their safe categories.

To use actual lab NGINX JSONL, first generate fresh localhost traffic while Docker is running. The agent reads up to 25 lines from the supplied file and rejects log rows older than five minutes. For a fresh log extract:

```bash
tail -n 25 simulations/runtime/logs/access.log > simulations/runtime/owner/step11_recent.jsonl
cybersentinel-agent --input simulations/runtime/owner/step11_recent.jsonl \
  --domain-id REPLACE_WITH_YOUR_VERIFIED_DOMAIN_ID
```

If the log contains stale entries older than five minutes, create fresh simulated traffic before extracting.

If you do not control a public DNS domain, use the automated unit tests. There is no bypass for ownership verification in the normal application.

## 11.6 Review and push

```bash
python -m scripts.normalize_dashes --check
python -m unittest discover -s tests -v
python -m scripts.release_audit
git add -u
git add owner_api/telemetry.py cybersentinel_agent/ pyproject.toml \
  scripts/normalize_dashes.py tests/test_step11_agent.py docs/HUONG_DAN_BUOC_11.md docs/OWNER_AGENT_SECURITY.md
git diff --cached --check
git diff --cached --stat
git status --short
git commit -m "feat: add local scoped telemetry agent and ingestion"
git push -u origin feat/local-agent-ingestion-step11
```

Create a PR into `main`, review all normalized text files, and merge only if all CI jobs pass. Never commit your SQLite DB, raw log samples, `.env`, or agent key.

## Step 11 limitations and next steps

- Owner API and agent are intentionally localhost-only. No account hosting, HTTPS ingress, or 24/7 daemon yet.
- Agent currently performs a one-shot bounded ingest; repeated execution can be automated in a controlled lab but reliable continuous log rotation/checkpointing is future work.
- Telemetry derives from NGINX logs supplied by the agent. Source attribution can be incorrect in proxied deployments; `remote_addr` is used only for HMAC, never sent verbatim.
- Authentication and retention controls are not audited for production. DNS verification only proves control of a particular DNS record at verification time, not permanent legal ownership.
- Step 12 can add time-window features independent of `simulation_run_id`, fixed-rule alerts, drift handling, and an owner-specific live dashboard. Never assume the current Isolation Forest is safe for operational decisions.
