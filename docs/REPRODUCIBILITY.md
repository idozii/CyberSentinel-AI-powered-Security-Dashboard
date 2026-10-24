# Reproducing the CyberSentinel Lab Experiment

## 1. Preconditions

- Run from the **repository root** on Linux/macOS (commands below use Bash).
- Python 3.12 or 3.13; Docker Engine and recent Docker Compose; available local ports 8080, 8001, 8501.
- Do not expose the demo services publicly, and do not replay attack-like traffic outside the local project lab.
- Generated data and models are local, **not stored in the Git repository**.

```bash
git switch main
git pull --ff-only origin main
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-ml.txt -r requirements-dashboard.txt
python -m unittest discover -s tests -v
python -m scripts.release_audit
```

Record the commit SHA (`git rev-parse HEAD`) and versions (`python --version`, `docker compose version`, `python -m pip freeze`) before comparing metrics between machines. Library dependency ranges permit version changes.

## 2. Generate an isolated local experiment

```bash
docker compose -f simulations/docker-compose.yml up --build -d --wait
curl --noproxy '*' -i http://127.0.0.1:8080/health
python -m scripts.run_lab_experiments --runs-per-class 40 --seed 42
```

The generator creates benign, brute-force, scan and mixed sessions; each is a **controlled simulation**. It rejects unexpected HTTP status patterns. The current code does not pause to guarantee each run lies inside one calendar-minute bucket, so the final number of windows may vary slightly.

```bash
RUN_DIR=$(find simulations/runtime/processed -maxdepth 1 -type d -name 'step5_*' | sort | tail -n 1)
echo "$RUN_DIR"
cat "$RUN_DIR/data_summary.json"
```

**Required invariants:** `matched_labeled_events == simulation_requests` and `manifest_records_without_event == 0`. Old access-log entries may be counted as unlabeled and excluded from features. Do not silently relabel them benign.

## 3. Fit and evaluate the baseline

```bash
python -m scripts.train_detector \
  --input "$RUN_DIR/window_features.csv" \
  --output-dir "$RUN_DIR/ml_results" \
  --seed 42 --target-fpr 0.05 --trees 200

cat "$RUN_DIR/ml_results/metrics.json"
cat "$RUN_DIR/ml_results/split_manifest.json"
```

Isolation Forest fits **only benign train windows**. The anomaly decision threshold is set from **benign validation windows only**. Do not inspect the test set to choose or move the threshold. Verify that no simulation run appears in multiple train/validation/test groups. `predictions.csv` records scores and decisions for validation and test. `isolation_forest.joblib` is local; deserialize **only your own trusted artifact**.

## 4. Frozen-model robustness audit

```bash
python -m scripts.audit_detector_robustness \
  --input "$RUN_DIR/window_features.csv" \
  --ml-results "$RUN_DIR/ml_results" \
  --output "$RUN_DIR/ml_results/robustness_report.json"
```

The audit verifies split consistency, threshold reproduction and held-out metric consistency before creating **hypothetical feature-space** changes. It does not provide an independent external test and must not be used to tune the frozen model while presenting the original test as untouched.

## 5. View the saved results offline

Terminal A:

```bash
source .venv/bin/activate
uvicorn dashboard_api.main:app --host 127.0.0.1 --port 8001
```

Terminal B:

```bash
source .venv/bin/activate
streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8501
```

Open `http://127.0.0.1:8501`. Stop background processes with Ctrl+C and shut down Docker lab when no longer needed:

```bash
docker compose -f simulations/docker-compose.yml down
```

## 6. Expected outputs

`simulations/runtime/processed/step5_<timestamp>_<suffix>/` contains:

```text
data_summary.json
labels.jsonl
raw/
events.csv
labeled.csv
window_features.csv
ml_results/
    metrics.json
    split_manifest.json
    predictions.csv
    isolation_forest.joblib
    robustness_report.json
```

These files are deliberately not committed. The example figures in [Experiment Results](EXPERIMENT_RESULTS.md) describe one recorded local run, not guaranteed outputs. CPU timing, minute boundaries, OS/network scheduling and package versions can change measured durations or window allocations.

## 7. Failure cases and checks

| Symptom | What to check |
|---|---|
| HTTP 502 on proxy startup | `docker compose -f simulations/docker-compose.yml ps -a` and `logs --tail=60 webapp proxy`; health check waits for demo webapp |
| No experiment in dashboard | Check local `simulations/runtime/processed/step5_*/window_features.csv` and API `/api/runs` |
| Label join strict failure | Verify NGINX-issued request IDs and access log; do not infer labels from status/User-Agent |
| Not enough independent runs | Increase lab runs (minimum in `stratified_run_split`); never weaken split requirements just to train |
| API responds 404 at `/` | Expected; use `/api/health` or `/docs` |
| GitHub shows no datasets | Expected: runtime output is excluded from version control |

## 8. Reporting checklist

Report (a) code SHA, (b) dataset-generation seed and counts, (c) Python/sklearn versions, (d) feature list and window size, (e) exact split manifest, (f) model and threshold protocol, (g) class distribution and prevalence, (h) confusion counts and precision/recall/F1/AP, and (i) all substantive limitations and failure cases. If the experiment is changed, archive a new report with a new date rather than rewriting earlier metrics.
