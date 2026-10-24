# CyberSentinel - Step 4: Window-Based Feature Engineering

## What this implements

- Fixed, non-overlapping 60-second windows aligned to UTC.
- Groups by **simulation run, source IP, service and time window** so different controlled runs cannot silently contaminate each other's labels.
- Computes 14 *numeric* behavior features. `request_id`, `source_ip`, `simulation_run_id`, `scenario_label`, `path`, and `user_agent` are NOT model input columns.
- Explicitly excludes `unlabeled` requests; never assumes missing labels mean benign.
- Assigns `simulated_mixed_attack` if multiple attack/benign labels occur within a window.
- Validates timestamps, duplicate request IDs and telemetry types; writes output atomically on success.

**Limitations:** run-specific windows are a controlled-lab expedient, not a live streaming intrusion detector. HTTP request features do not generalize automatically to DDoS or phishing. The simulation is small and deterministic; do not claim model accuracy from it. The next step must use more varied runs and run-wise train/test separation.

## Installation and test (Linux terminal, repository root)

1. Ensure any local changes are saved/committed or safely stashed before switching.
2. `git switch main && git pull --ff-only origin main && git switch -c feat/window-feature-engineering`
3. Unzip the provided archive at the **repository root**, not inside `scripts`.
4. `python -m unittest discover -s tests -v` (expect **31** tests if the existing **19** remain unchanged).

## Generate a feature CSV from an existing Step 3 output

Set a correct folder that contains `labeled.csv`:

```bash
OUT_DIR=simulations/runtime/processed/<YOUR_PREVIOUS_RUN_TAG>
python scripts/build_window_features.py \
  --input "$OUT_DIR/labeled.csv" \
  --output "$OUT_DIR/window_features.csv" \
  --window-seconds 60
```

If your previous dataset has not been created, re-run Step 3 first:

```bash
docker compose -f simulations/docker-compose.yml up --build -d --wait
RUN_TAG=$(date +%Y%m%d_%H%M%S)
RAW_DIR="simulations/runtime/raw/$RUN_TAG"
OUT_DIR="simulations/runtime/processed/$RUN_TAG"
MANIFEST="$OUT_DIR/labels.jsonl"
python scripts/attack_replay.py --scenario benign --attempts 10 --concurrency 3 --manifest-path "$MANIFEST"
python scripts/attack_replay.py --scenario mixed --attempts 5 --concurrency 3 --manifest-path "$MANIFEST"
python scripts/collector.py --input simulations/runtime/logs/access.log --output-dir "$RAW_DIR" --target-service webapp
python scripts/etl.py --input-dir "$RAW_DIR" --output "$OUT_DIR/events.csv" --format csv
python scripts/build_labeled_dataset.py --events "$OUT_DIR/events.csv" --manifest "$MANIFEST" --output "$OUT_DIR/labeled.csv" --strict
python scripts/build_window_features.py --input "$OUT_DIR/labeled.csv" --output "$OUT_DIR/window_features.csv" --window-seconds 60
```

You should see `labeled_events: 23` in the Step 4 JSON summary when you use 10 benign + 5 brute-force + 8 scan requests from a clean run. You may have other events in `labeled.csv`; they should be counted as `skipped_unlabeled_events`. The exact *number of windows* depends on wall-clock timing and grouping; do not assume it must equal 23 or 3.

Inspect output:

```bash
head -n 5 "$OUT_DIR/window_features.csv"
python -m unittest discover -s tests -v
git status
```

Stop lab when no longer needed:

```bash
docker compose -f simulations/docker-compose.yml down
```

Do not commit any runtime logs or generated CSVs. When tests and checks pass:

```bash
git add scripts/model_features.py scripts/build_window_features.py tests/test_window_features.py
git diff --cached --stat
git commit -m "feat: add time-window HTTP behavior features"
git push -u origin feat/window-feature-engineering
```

Create a PR into `main` and review before merging.

## Specific feature schema

`request_count`, `request_rate_per_second`, `get_ratio`, `post_ratio`, `login_attempt_count`, `failed_login_count`, `unique_path_count`, `http_401_ratio`, `http_404_ratio`, `http_4xx_ratio`, `query_ratio`, `mean_duration_ms`, `mean_request_bytes`, `mean_response_bytes`.

The following are **metadata**, not features: window_start, window_end, window_seconds, service, source_ip, simulation_run_id, scenario_label, label_source.

## Important ML caveats

- Treat `simulation_run_id` as a grouping/splitting identifier, never an input feature. Even run-wise splitting on just two runs is not a valid ML evaluation.
- A script that generates every benign request against `/health` and every malicious request against `/login` can produce a trivial dataset. Use additional normal patterns and varied attack runs before evaluating.
- Source IP is user-influenced in this local simulation and must not be treated as a trusted identity without appropriate proxy configuration.
- `failed_login_count` derives from 401 responses on POST /login and can be informative but is application-specific; do not overstate cross-service generalization.
