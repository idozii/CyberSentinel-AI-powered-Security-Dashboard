# CyberSentinel - Publish a Streamlit portfolio showcase

> This deployment is a **static research showcase** with real reported, *aggregated* results from the controlled 24 October 2026 localhost experiment. It is **not** the local dashboard backed by FastAPI, not live threat monitoring, and not an operational IDS.

## Why use a separate entrypoint?

`dashboard/app.py` requires an API at `127.0.0.1:8001` and experiment files in the ignored `simulations/runtime/processed/` directory. On Streamlit Community Cloud, `127.0.0.1` refers to the cloud app's own machine, not the developer's laptop; neither the laptop API nor the ignored data is present in a GitHub checkout.

The new **`dashboard/public_app.py`** is self-contained and reads only **`dashboard/public_metrics.json`**. It deliberately does not load ML artifacts, read raw logs or call the internal API. The original local FastAPI + Streamlit workflow is preserved and unchanged.

## 1. Install in the repo

At the **repository root**, from a clean `main`:

```bash
git status
git switch main
git pull --ff-only origin main
git switch -c feat/public-streamlit-showcase
```

Unzip the supplied bundle **at repository root**. Confirm paths:

```bash
ls dashboard/public_app.py dashboard/public_data.py dashboard/public_metrics.json dashboard/requirements.txt
ls tests/test_public_showcase.py docs/PUBLIC_DEPLOYMENT.md
```

Run tests:

```bash
source .venv/bin/activate   # if you have a local venv
python -m unittest discover -s tests -v
python -m scripts.release_audit
```

Optional local public preview (different port from the existing dashboard):

```bash
python -m pip install -r dashboard/requirements.txt
streamlit run dashboard/public_app.py --server.address 127.0.0.1 --server.port 8502
```

Open `http://127.0.0.1:8502`. You do **not** need FastAPI or Docker for this preview.

## 2. Commit and PR

```bash
git add dashboard/public_app.py dashboard/public_data.py dashboard/public_metrics.json \
  dashboard/requirements.txt tests/test_public_showcase.py docs/PUBLIC_DEPLOYMENT.md
git diff --cached --name-status
git diff --cached --check
git commit -m "feat: add public aggregate-only Streamlit showcase"
git push -u origin feat/public-streamlit-showcase
```

Create a GitHub PR targeting `main`, review and merge after CI succeeds.

## 3. Deploy to Streamlit Community Cloud

1. Open <https://share.streamlit.io/> and sign in with GitHub.
2. Choose **Create app** → **Yup, I have an app** (wording may vary).
3. Select **GitHub repo**: `idozii/CyberSentinel-AI-powered-Security-Dashboard`.
4. Select **branch**: `main`.
5. Set **entrypoint**: `dashboard/public_app.py` (NOT `dashboard/app.py`).
6. If offered an app subdomain, choose a meaningful available name, e.g. `cybersentinel-research-demo`. This is a suggested name, **not an existing URL**.
7. Under **Advanced settings**, select Python **3.12** if available; this project has CI coverage on 3.12/3.13. No secrets needed.
8. Click **Deploy**. Wait for successful deployment and open the actual link issued by Streamlit.
9. Ensure the app is **public** if your aim is for any visitor to be able to open the link.

Streamlit Community Cloud should discover `dashboard/requirements.txt`, because it is alongside the entrypoint file. There is no root `requirements.txt` in this repo, only `requirements-dashboard.txt`/`requirements-ml.txt`, so the public app's minimal dependency file prevents unnecessary installation.

## 4. Verify the hosted app

- Overview shows **2,678 simulated requests**, **160 windows**, and **0 manifest gaps**.
- Traffic & Features shows **40 windows** for each simulation class.
- Model Evaluation (test) shows **Isolation Forest recall 29.17%**, F1 **45.16%**, scanning detection **0/8**.
- Architecture & Limitations clearly says the showcase is *static and experimental*.
- Links to the GitHub repository and experiment report work.
- Open the hosted URL in a private/incognito browser session to verify public access.
- No raw logs, model files, credentials, or internal network service is reachable.

## 5. Add the real URL to README

After deployment succeeds, append a **Public demo** paragraph near the top of `README.md`:

```markdown
### Public showcase

[Open CyberSentinel research dashboard](https://YOUR-REAL-STREAMLIT-URL.streamlit.app/)

A static showcase of anonymized, aggregate results from a controlled local experiment; no live attack monitoring or live model inference.
```

Use the actual URL provided in your Streamlit workspace; do not assume the subdomain is available.

## Important limitations

- The public static dashboard does not show all 160 row-level windows or request-level log records. Those remain local in the full experimental system.
- The reported scores are from one local run; training is **not** rerun in the cloud.
- F1/recall for the fixed-rule baseline must not be presented as real-world detection accuracy.
- For a truly dynamic multi-user system, host a separately secured backend and persistent data store, implement authentication and privacy controls, and redesign window grouping to eliminate dependencies on simulation run IDs.

Official docs: <https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/deploy> and <https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/app-dependencies>.
