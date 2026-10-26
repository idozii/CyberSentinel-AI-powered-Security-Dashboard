# CyberSentinel - Local Setup & First-Time User Guide

**Clone it. Run it. Explore it. No Neon, Auth0, paid database, or cloud account required.**

CyberSentinel is a local-first **security telemetry research and demonstration project**. You can explore saved research results, run a safe interactive SOC-style alert demonstration, or reproduce a synthetic NGINX-to-ML experiment on your own machine. The public website is a *showcase*, not the backend of a hosted monitoring product.

> **Important:** This is a research/educational prototype, **not** a production intrusion detection system (IDS). All generated attack-like traffic must remain inside the supplied localhost lab. Never point these scripts at third-party websites or real systems.

## 1. Choose what you want to try

| Mode | What you get | Difficulty | Docker? | Accounts/domain? |
|---|---|---|---|---|
| **A. Research dashboard** | Streamlit overview, charts and published synthetic experiment results | Easy; recommended first | No | No |
| **B. Interactive SOC demo** | Generate mock NGINX events, submit through a local agent, inspect and acknowledge rule alerts | Beginner/intermediate | No | No |
| **C. Full AI experiment** | Reproduce localhost traffic, ETL, 60-second windows, Isolation Forest and FastAPI/Streamlit explorer | Intermediate | **Yes** | No |
| **D. Local owner platform (optional)** | Local SQLite account, verified domain, agent keys and persistent local monitoring | Advanced | Not required for onboarding | **Control of a public DNS domain for agent-key issuance** |

**Start with A, then B.** Mode C is for people who want to understand or extend the machine-learning pipeline. Mode D is optional and is *not* needed for the interactive demo.

## 2. Prerequisites and first clone

These commands are intended for **Ubuntu/Linux Bash and macOS Bash**. On macOS, run `bash` first if your default shell is Zsh, because the hidden-key `read` commands below use Bash flags. On Windows, use **WSL2 Ubuntu** for the same terminal workflow (Docker Desktop with WSL integration is required for Mode C). You need:

- **Git** and **Python 3.12 or 3.13**, including `venv` and `pip`.
- Internet access **once** to clone the repository and download Python dependencies. The local demonstrations do not require a paid cloud service.
- Browser access to `127.0.0.1` on your own computer.
- For **Mode C only**: working Docker Engine / Docker Desktop and Docker Compose.

Check your installation:

```bash
python3 --version  # Python 3.12.x or 3.13.x
python3 -m pip --version
git --version
```

If `python3` is an unsupported version, use an installed `python3.12` or `python3.13` to create the virtual environment instead. On Ubuntu, if `venv` is missing, install the matching Python `venv` package for your distribution.

**Run these commands in a new terminal:**

```bash
git clone https://github.com/idozii/CyberSentinel-AI-powered-Security-Dashboard.git
cd CyberSentinel-AI-powered-Security-Dashboard

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python --version
```

You should see `(.venv)` in your shell prompt or verify that `python` points to the virtual environment. Do **not** use `sudo pip install`. All further commands below assume you are in the **repository root** with the virtual environment activated.

> **New clone?** Everything you need is already on `main`. Do not create an old feature branch, unzip historical milestone patches, or run old Git instructions found in numbered development notes.

---

## 3. Mode A - Open the research dashboard (fastest path)

**Use this mode when you want to see the project immediately.** It reads the bundled `dashboard/public_metrics.json`, so you do not have to generate any traffic or train a model first.

Install the minimal dashboard dependencies:

```bash
python -m pip install -r requirements-dashboard.txt
```

Validate the included research summary and launch Streamlit:

```bash
python -m scripts.zero_cost_portfolio audit
python -m scripts.zero_cost_portfolio demo
```

Open **http://127.0.0.1:8501** in your browser. The terminal remains occupied while the app runs. Press **Ctrl+C** to stop it.

**What to look for:**

- Security overview and simulated traffic composition.
- 160 synthetic analysis windows from a previously recorded local experiment.
- 2,678 simulated HTTP requests recorded in the bundled research summary.
- Isolation Forest holdout recall of **29.17% (7/24 detected)**, including **0/8 detected path-scanning windows**.
- The architecture and experiment limitations.

These figures are **bundled, user-reported controlled-lab results**, not freshly recomputed performance or real-world security accuracy. The website checker is intentionally **disabled** by this offline launcher. The public Streamlit showcase may display it under its separate passive HTTPS policy.

**If port 8501 is already taken:**

```bash
python -m scripts.zero_cost_portfolio demo --port 8502
```

### Optional: generate a standalone evidence report

```bash
python -m scripts.zero_cost_portfolio audit --output /tmp/cybersentinel-evidence-1.html
```

Open `/tmp/cybersentinel-evidence-1.html` in your browser. The output path must **not already exist**, and reports must be written **outside the Git repository**. Pick a new filename for another report.

---

## 4. Mode B - Try the interactive SOC alert demo (no cloud or DNS)

This is the most useful hands-on introduction. Unlike Mode A, it demonstrates the **agent -> local ingest -> alerts -> SOC UI** flow with freshly generated synthetic events. The demo has **one fake tenant, an in-memory store, and no persistent database**.

### 4.1 Install the demo dependencies

From the same activated environment:

```bash
python -m pip install -r requirements-dashboard.txt -r requirements-owner.txt -r requirements-hosted.txt
python -m pip install -e .
```

### 4.2 Start the local SOC app (Terminal 1)

```bash
python -m scripts.step25_demo
```

Open **http://127.0.0.1:8019/**. Select **Generate new local demo key**. The page displays:

- **Demo Domain ID**: a synthetic identifier for this session (copy it).
- **Agent key**: begins with `csd_` (copy it privately; it is shown only once).

**Do not use a real credential, domain, Neon DSN, or Auth0 token.** The demo does not need any of these. Leave Terminal 1 running. If the command refuses to start because cloud credentials are present in your environment, open a clean shell without those values.

### 4.3 Create and send five synthetic login events (Terminal 2)

Open a **second terminal**, change to the cloned repository and activate its virtual environment:

```bash
cd /path/to/CyberSentinel-AI-powered-Security-Dashboard  # Replace with your local clone path
source .venv/bin/activate

# Paste the demo agent key when prompted. Your input is hidden.
read -rsp 'Demo agent key: ' CYBERSENTINEL_AGENT_KEY; echo
export CYBERSENTINEL_AGENT_KEY

# Paste the Demo Domain ID from the local dashboard.
read -rp 'Demo Domain ID: ' DEMO_DOMAIN_ID

# Make a unique temporary filename (generator refuses to overwrite files).
LOG_FILE="/tmp/cs-login-$(python -c 'import uuid; print(uuid.uuid4().hex[:10])').jsonl"
python -m scripts.step19_generate_logs --scenario login --output "$LOG_FILE"

# Validate first: no events are transmitted in a dry run.
cybersentinel-demo-agent --input "$LOG_FILE" --domain-id "$DEMO_DOMAIN_ID" --dry-run

# Submit only to the demo running at 127.0.0.1:8019.
cybersentinel-demo-agent --input "$LOG_FILE" --domain-id "$DEMO_DOMAIN_ID"
```

**Expected on a healthy first run:** `submitted: 5`, `accepted: 5`, `duplicates: 0`, `alerts_updated: 1`. The exact console representation can differ; if an event expires or the token was replaced, generate fresh events and retry with the active key.

Return to **http://127.0.0.1:8019/** and refresh the page. Look for **Repeated login failures**, open the alert details, filter/triage, and try **Acknowledge**.

### 4.4 Test deduplication

Within **five minutes of generating the log**, resend the **same file**:

```bash
cybersentinel-demo-agent --input "$LOG_FILE" --domain-id "$DEMO_DOMAIN_ID"
```

The demo should return `accepted: 0` and `duplicates: 5`. This shows idempotent event handling in the local demonstration, not distributed production delivery.

### 4.5 Try another type of alert (optional)

```bash
LOG_404="/tmp/cs-404-$(python -c 'import uuid; print(uuid.uuid4().hex[:10])').jsonl"
python -m scripts.step19_generate_logs --scenario 404 --output "$LOG_404"
cybersentinel-demo-agent --input "$LOG_404" --domain-id "$DEMO_DOMAIN_ID"
```

Refresh the browser to inspect the **HTTP 404 response burst** alert. The generator also supports `--scenario 5xx` and `--scenario traffic`; the installed `cybersentinel-demo-agent` splits a 40-event traffic demo into batches of up to 25 events.

**Stop and reset:** Press Ctrl+C in Terminal 1. Events, alerts, keys and synthetic domain ID are **lost when the process stops**. Starting again begins an empty session. Then, in Terminal 2:

```bash
unset CYBERSENTINEL_AGENT_KEY DEMO_DOMAIN_ID
```

If you only want a noninteractive automated smoke test, run:

```bash
python -m scripts.step25_release
```

---

## 5. Mode C - Reproduce the full NGINX and AI experiment

**Use this mode when you want new data and a retrained model rather than the static published metrics.** No Neon, Auth0, cloud account, or public website is involved.

### 5.1 Install dependencies and verify Docker

```bash
python -m pip install -r requirements-ml.txt -r requirements-dashboard.txt

docker compose version
docker info
```

If `docker info` fails, start the Docker daemon/Desktop and check that your user can run Docker commands. Docker must have enough available memory and disk space for its local lab.

### 5.2 Start the restricted NGINX lab

```bash
docker compose -f simulations/docker-compose.yml up --build -d --wait
curl --noproxy '*' http://127.0.0.1:8080/health
```

The `/health` endpoint should return a healthy response. **All attack-like simulations must target only the provided `127.0.0.1:8080` lab.**

### 5.3 Generate new labeled traffic and feature windows

```bash
python -m scripts.run_lab_experiments --runs-per-class 40 --seed 42

RUN_DIR=$(find simulations/runtime/processed -maxdepth 1 -type d -name 'step5_*' | sort | tail -n 1)
echo "$RUN_DIR"
cat "$RUN_DIR/data_summary.json"
```

Check that `RUN_DIR` is **not empty**. In the summary, check these data-quality invariants:

- `matched_labeled_events == simulation_requests`
- `manifest_records_without_event == 0`
- Any unrelated historical NGINX log entries remain **unlabeled**; they are not automatically treated as benign.

Exact request counts and window allocations can vary with local timing, scheduling and library versions.

### 5.4 Train and audit Isolation Forest

```bash
python -m scripts.train_detector \
  --input "$RUN_DIR/window_features.csv" \
  --output-dir "$RUN_DIR/ml_results" \
  --seed 42 --target-fpr 0.05 --trees 200

cat "$RUN_DIR/ml_results/metrics.json"

python -m scripts.audit_detector_robustness \
  --input "$RUN_DIR/window_features.csv" \
  --ml-results "$RUN_DIR/ml_results" \
  --output "$RUN_DIR/ml_results/robustness_report.json"
```

The baseline fits on benign training windows and calibrates its threshold using benign validation windows. **Do not retune using test results** and still call the test untouched. Only open/deserialise `.joblib` models you generated and trust.

### 5.5 Open the detailed experiment explorer

Keep the environment activated. Use **two terminals**:

**Terminal A:**

```bash
uvicorn dashboard_api.main:app --host 127.0.0.1 --port 8001
```

**Terminal B:**

```bash
streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8501
```

Open **http://127.0.0.1:8501** and choose the freshly generated experiment. You can inspect **Overview, Traffic Explorer, Model Evaluation and Robustness**. To verify the API directly:

```bash
curl --noproxy '*' http://127.0.0.1:8001/api/health
curl --noproxy '*' http://127.0.0.1:8001/api/runs
```

If no runs appear, ensure Step 5.3 completed and that `simulations/runtime/processed/step5_*/window_features.csv` exists. A fresh clone **does not contain prior experiment outputs** because Git ignores local runtime data.

**Finish:** Stop both Python services with Ctrl+C, then stop the lab containers:

```bash
docker compose -f simulations/docker-compose.yml down
```

The generated artifacts stay in your ignored `simulations/runtime/processed/` directory unless you remove them yourself.

---

## 6. Mode D - Optional persistent local Owner/Agent platform

This mode is **not** needed for Mode A, B or C. It uses a local **SQLite** owner database, not Neon/Auth0. Unlike the fake one-tenant Mode B demo, its normal onboarding requires actual control of a public DNS hostname before agent keys may be issued.

Install once:

```bash
python -m pip install -r requirements-dashboard.txt -r requirements-owner.txt
python -m pip install -e .
```

Then run **two terminals**:

**Terminal A:**

```bash
uvicorn owner_api.main:app --host 127.0.0.1 --port 8002
```

**Terminal B:**

```bash
streamlit run owner_portal/app.py --server.address 127.0.0.1 --server.port 8503
```

Open **http://127.0.0.1:8503**. Register a **local-only** account using a unique test password; log in, add a domain **you actually control**, publish the displayed DNS TXT challenge and verify it before issuing an agent key. The SQLite database resides under the ignored `simulations/runtime/owner/` directory. Do not upload it or its secrets to GitHub.

**No public domain?** Use **Mode B** instead. Do not bypass domain verification or claim a third party's domain. For the detailed owner/agent workflow, see [`docs/HUONG_DAN_BUOC_10.md`](HUONG_DAN_BUOC_10.md), [`docs/HUONG_DAN_BUOC_11.md`](HUONG_DAN_BUOC_11.md), and [`docs/HUONG_DAN_BUOC_13.md`](HUONG_DAN_BUOC_13.md). Historical branch/unzip instructions in those development documents are **not required** for a current clone of `main`.

---

## 7. Quality checks for contributors and reviewers

**Do not run the entire test suite with only the minimal Mode A installation**: it exercises owner, hosting and ML components as well. First install all requirements:

```bash
python -m pip install -r requirements-ml.txt \
  -r requirements-dashboard.txt \
  -r requirements-owner.txt \
  -r requirements-hosted.txt
python -m pip install -e .

python -m unittest discover -s tests -v
python -m scripts.release_audit
python -m scripts.normalize_dashes --check
python -m scripts.zero_cost_portfolio audit
python -m scripts.zero_cost_portfolio audit --full
python -m scripts.portfolio_finalizer
```

Several PostgreSQL integration tests are intentionally **SKIPPED** on personal computers. They require special disposable PostgreSQL 17 and GitHub Actions safeguards, and are verified in the repository's CI. Check the **latest** workflow run on [GitHub Actions](https://github.com/idozii/CyberSentinel-AI-powered-Security-Dashboard/actions); do not mistake local skips for a production authorization guarantee.

To record a portable, standalone source-evidence report (new filename only):

```bash
python -m scripts.zero_cost_portfolio audit --output /tmp/cybersentinel-review-1.json
```

---

## 8. Common problems and solutions

| Problem | Likely cause | Fix |
|---|---|---|
| `python: command not found` or incorrect version | Virtual environment not active / wrong Python | `source .venv/bin/activate`; check `python --version` |
| `No module named streamlit`, `fastapi`, `jwt`, `dns`, etc. | Incomplete dependencies | Activate `.venv`, install the requirements for your chosen mode; install **all four** requirement files for full tests |
| `Address already in use` on 8501/8019/8001/8002/8503 | Another local process uses the port | Stop the older process; Mode A supports `demo --port 8502`; do **not** change host to `0.0.0.0` |
| Research dashboard shows no new experiment | You opened Mode C explorer before generating data | Run Sections 5.2-5.4, then check `/api/runs`; use Mode A for bundled metrics |
| `docker: command not found` or daemon unavailable | Docker not installed/started | Install Docker Engine/Desktop and enable Docker Compose; required only for Mode C |
| NGINX lab health fails / 502 | Containers still starting or failed | `docker compose -f simulations/docker-compose.yml ps -a` and `docker compose -f simulations/docker-compose.yml logs --tail=60 webapp proxy` |
| Agent returns 401 | Wrong or replaced demo key / Domain ID | Generate a new key at 8019, copy the new Domain ID, export the matching `csd_` key |
| Agent rejects stale events | Synthetic timestamps are more than five minutes old | Generate a **new** JSONL with a **new filename** and submit immediately |
| `File already exists` on report or synthetic log | The tools intentionally refuse overwrites | Choose a unique filename outside the repo |
| Owner domain not verified | No public TXT record / DNS propagation pending | Verify only a domain you control, or use Mode B without DNS |
| Some PostgreSQL tests are skipped locally | Expected CI-only isolation guard | Verify the repository's PostgreSQL GitHub Actions job; do not force the guard off |
| New clone has no model/data artifacts | `simulations/runtime/` is Git-ignored | Run Mode C, or use Mode A's bundled research summary |

You can inspect the existing detailed debugging guide in [`docs/REPRODUCIBILITY.md`](REPRODUCIBILITY.md).

---

## 9. Safety, privacy and honest interpretation

- **Bind all local services to `127.0.0.1`.** Never expose the Owner API, interactive SOC demo, SQLite files, demo keys or the experimental tenant APIs directly to the public internet.
- Use **synthetic logs only** for your first trial. No attack traffic against outside websites, no real customers, and no imported secrets or private records.
- Avoid sharing `.env`, database DSNs, tokens, local SQLite databases, raw request logs, and generated `.joblib` models. Those are excluded from Git for good reason.
- The isolated PostgreSQL/OIDC tests are *security proofs in a disposable CI database*, not evidence that the optional shared-role hosted staging implementation is production safe.
- A green CI badge is not a security certification. CyberSentinel does **not** claim reliable real-world intrusion detection: the recorded Isolation Forest missed **17/24** simulated attack windows, including **all eight scanning windows**.
- Mode A is a static research showcase. Mode B is a synthetic in-memory demonstration. Mode C is a reproducible local experiment. Mode D is a separate local prototype with stricter domain-verification rules.

## 10. Quick success checklist

- [ ] Cloned the repository and created an isolated Python virtual environment.
- [ ] Ran **Mode A** and opened the research dashboard at `127.0.0.1:8501`.
- [ ] (Recommended) Ran **Mode B**: generated a local key, submitted five events, saw a rule alert, then verified duplicate handling.
- [ ] (Optional) Ran **Mode C**: generated new NGINX traffic, trained Isolation Forest, and viewed an experiment in the local explorer.
- [ ] Stopped local listeners and Docker containers when finished.
- [ ] Understood that the published results are synthetic and that public SaaS is **not** available.

**Questions or a reproducible bug?** Open a [GitHub issue](https://github.com/idozii/CyberSentinel-AI-powered-Security-Dashboard/issues) with your OS, Python version, mode (A/B/C/D), the exact command you ran, and the error message **with all keys, tokens, DSNs and personal data removed**.

---

*Source reference: current CyberSentinel repository (`main`), with the Zero-Cost Portfolio, interactive Step 25 SOC demo, Step 5-6 research pipeline, and optional local Owner API. Instructions are intended for a clean checkout, not a historical milestone ZIP.*
