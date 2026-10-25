# CyberSentinel - Buoc 33-35: Durable Agent Bridge & Recovery

Scope: extend the existing Step 13 SQLite outbox to existing Step 19 Local Demo
and Step 18 PostgreSQL staging ingest, with a read-only state doctor. This does
NOT introduce a queue backend, production rollout or HTTP freshness bypass.

## 0. Apply the ZIP on latest main

```bash
cd ~/Desktop/CyberSentinel-AI-powered-Security-Dashboard
git status
git switch main
git pull --ff-only origin main
git switch -c feat/durable-agent-bridge-step33-35
unzip -o ~/Downloads/CyberSentinel_Buoc_33_35_Durable_Agent.zip -d .
source /home/idozii/envs/ds/bin/activate
python -m pip install -e .
```

## 1. Step 33 - Continuous agent to localhost demo

Start localhost Demo on port 8019 (not a public interface):

```bash
python -m scripts.step25_demo
```

In the browser at http://127.0.0.1:8019/, create a **new** local demo key,
copy the `csd_` secret once, and note the Demo Domain ID. In a separate terminal:

```bash
source /home/idozii/envs/ds/bin/activate
printf 'Demo agent key: '
IFS= read -rs CYBERSENTINEL_AGENT_KEY
printf '\n'
export CYBERSENTINEL_AGENT_KEY
python -m scripts.step19_generate_logs --scenario login --output /tmp/cs-step33-login.jsonl
python -m cybersentinel_agent.watch_cli \
  --input /tmp/cs-step33-login.jsonl \
  --domain-id YOUR_DEMO_DOMAIN_ID \
  --state simulations/runtime/owner/demo-step33.sqlite3 \
  --server http://127.0.0.1:8019 --from-start --iterations 2
```

Do not share the key and do not insert it into a terminal command line or Git.
Use `--from-start` only on the *first* run of a new state. Later, omit it.

Existing watch support for `csa_` on port 8002 remains unchanged. `csp_` keys
are only sent to the local PostgreSQL staging ingest at 8008 or an approved HTTPS
origin. Such staging keys still require ownership verification in the real portal.
The existing Step 14 legacy `csa_` HTTPS bridge remains supported with an
explicitly pinned hostname. There is no DNS bypass and no migration in this patch.

## 2. Step 34 - Inspect pending queue without modifying state

```bash
python -m cybersentinel_agent.state_cli --state simulations/runtime/owner/demo-step33.sqlite3
```

Inspect only with a 600-permission regular SQLite file. The output contains
counts, age, cursor count and risk status; it excludes token, identifiers and
raw log lines. An exit code 2 indicates a problem or an unsafe state.

If the agent is offline and the oldest queued event approaches 5 minutes, stop
and investigate before continuing. The APIs deliberately reject stale events;
replaying them cannot rescue them. The existing `--purge-expired --confirm-loss`
is destructive and should be used only after investigation, explicit approval,
and keeping an incident note. The command cannot repair long-outage gaps.

For key rotation, **stop the watcher, drain or document the old queue, issue a
new key and use a new SQLite state file**. State is intentionally bound to the
original key, domain and log path. Rotating keys does not automatically migrate
or clear pending data.

## 3. Step 35 - Regression and release rehearsal

```bash
python -m unittest discover -s tests -p test_step33_35_delivery.py -v
python -m scripts.step33_35_preflight
python -m scripts.step35_release
python -m unittest discover -s tests -v
python -m scripts.normalize_dashes --check
python -m scripts.release_audit
```

The test suite simulates a failed network and a lost HTTP acknowledgement;
restarting the SQLite follower retransmits and the demo server deduplicates
instead of creating repeated alerts. It also checks that demo keys cannot be
sent to staging, a read-only diagnostic does not leak identifying data, and
old/stale events are never silently discarded. CI additionally covers the
PostgreSQL isolation tests in a dedicated job.

## 4. Commit once

```bash
git diff --check
git status
git add README.md pyproject.toml .github/workflows/ci.yml \
  cybersentinel_agent/continuous.py cybersentinel_agent/state_cli.py \
  scripts/step33_35_preflight.py scripts/step35_release.py \
  tests/test_step33_35_delivery.py docs/HUONG_DAN_BUOC_33_35.md \
  docs/STEP33_35_DELIVERY_LIMITATIONS.md
git diff --cached --check
git commit -m "feat: bridge durable agent outbox to demo and staging with recovery checks"
git push -u origin feat/durable-agent-bridge-step33-35
```

Open GitHub PR against main. Verify GitHub CI before merging. NEVER expose
localhost demo publicly. Beta readiness remains NO-GO.
