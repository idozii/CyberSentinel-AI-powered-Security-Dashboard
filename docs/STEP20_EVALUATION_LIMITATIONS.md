# Step 20 - Evaluation scope, threat model and evidence

## What is actually evaluated

- An offline harness creates a fresh Step 19 `DemoStore` for each labeled synthetic scenario.
- It calls the real `DemoStore.ingest()` path using transient `csd_` test bearer tokens held only in memory. No actual HTTP server, external network request, Neon database or Auth0 connection is needed.
- The benchmark replays every event ID and asserts idempotent deduplication.
- Each scenario has manually assigned expected rule labels. A prediction is whether the corresponding alert exists for that rule in that isolated scenario.
- The binary evaluation unit is **one (scenario, rule) pair**. The confusion matrix therefore has `14 x 4 = 56` elements, *not* 56 attacks, and should not be treated as representative operating prevalence.
- Precision = TP / (TP + FP); recall = TP / (TP + FN); F1 = 2TP / (2TP + FP + FN). Undefined denominators are shown as `N/A`.

## Expected illustrative findings for the included fixtures

- Four threshold-crossing scenarios generate the expected rule alert.
- Benign missing links and benign high-rate health polls generate two intentionally labeled false alarms.
- Low-rate suspicious login attempts and low-rate suspicious path probes are two intentionally labeled misses.
- Other below-threshold and split-source cases remain silent.
- Current expected aggregate: TP=4, FP=2, FN=2, TN=48; micro precision=recall=F1=0.6667.
- Results are bound to a SHA-256 digest of the rule/scenario manifest. Changes to rules or scenarios require reading the new report rather than reusing the expected scores.

## What is NOT evaluated

- No production attack detection rate, intrusion labels, field-collected benign populations or precision at realistic class prevalence.
- No ML Isolation Forest quality or generalization, adversarial robustness, high-load/concurrency testing, incident response time or model drift.
- No Neon PostgreSQL ingestion/RLS, DNS ownership, production OAuth, TLS exposure, external traffic or operational reliability.
- No inference that an HTTP 401/404/5xx pattern proves malicious intent.
- No security certification, third-party penetration test or production readiness claim.

## Safety and privacy design

- The evaluator does not take a log or CSV file as input and never reads customer, user or production telemetry.
- Secrets (`csd_` demo keys) are used transiently to exercise `DemoStore.ingest` but are not serialized in JSON, Markdown or HTML.
- All source references and event IDs are derived from synthetic scenario names, not network addresses or user IDs.
- The HTML route `/demo/evaluation` is attached only to the existing opt-in, one-worker, loopback-only Step 19 app; it cannot operate with the demo flag disabled.
- Evaluation uses independent stores and never mutates the active demo dashboard store, including its issued agent key.
- CLI report output must be directed to a brand new directory outside the source repository; it refuses overwrites and creates files with owner-only permissions.
- Preserve strict host/origin checks, CSRF forms, and the ban on public exposure of `127.0.0.1:8019`.

## Later work

For scientific claims, gather consented and de-identified ground-truth traffic from an owned lab, split by time/source into train/validation/test, document realistic base rates, and include confidence intervals, alert latency, calibration and cost-sensitive false positives. Those are intentionally not part of this synthetic benchmark.
