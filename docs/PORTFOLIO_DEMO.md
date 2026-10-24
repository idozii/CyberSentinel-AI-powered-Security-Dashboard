# Portfolio Demo and Project Presentation Checklist

## Recommended 3–5 minute demo

1. **Problem (30 sec).** Explain why individual HTTP requests may be uninformative and why 60-second behavioral windows are a useful *experimental* abstraction. Explicitly state the system is localhost-only, offline analysis.
2. **Architecture (45 sec).** Walk through `NGINX → collector/ETL → request_id label join → 14 numeric features → group-separated ML → FastAPI/Streamlit`. Show [Architecture](PROJECT_ARCHITECTURE.md).
3. **Demonstration (60 sec).** Start FastAPI + Streamlit from [Reproducibility](REPRODUCIBILITY.md), open Overview and Traffic Explorer. Show label matching (2,678 requests, zero manifest gaps) and a few windows.
4. **Model evidence (60 sec).** Show Model Evaluation: Isolation Forest test recall **29.17%**, F1 **45.16%**, and zero scanning recall. Compare the fixed-rule baseline and explain why the synthetic patterns make this a weak real-world benchmark.
5. **Quality and limitations (45 sec).** Show the green CI jobs, robustness page and [Security & limitations](SECURITY_AND_LIMITATIONS.md). Describe one concrete next experiment: adding diverse legitimate errors and independently held-out scan templates.

## Screenshot guidance

Capture screens from **your own working local dashboard** without browser tabs containing private information. Suggested filenames if you decide to commit them: `docs/images/overview.png`, `docs/images/traffic-explorer.png`, `docs/images/model-evaluation.png`, `docs/images/robustness.png`. Add images to README only after the corresponding files exist. Avoid publishing private logs, IP addresses from real users, `.env` or joblib model artifacts. The project works without screenshots.

## GitHub release checklist

- [ ] README reflects implemented components rather than aspirational React/Elasticsearch targets.
- [ ] Instructions work from a clean checkout with a blank runtime data directory.
- [ ] CI checks pass for Python 3.12, 3.13 and Docker smoke.
- [ ] Restored Step 4–7 guides exist in `docs/`.
- [ ] `python -m scripts.release_audit` completes successfully.
- [ ] `git diff --cached --name-status` contains no `.env`, runtime logs, processed CSVs, or `.joblib` artifacts.
- [ ] Experiment report discloses class prevalence, sample size, false negatives and data-generation limitations.
- [ ] Dashboard is accurately described as *offline* and *read-only*, not real-time threat protection.
- [ ] Links in README resolve to committed repository files.

## Useful discussion points for an AI/Data Science interview

- **Data provenance:** separation of telemetry and trusted simulation labels using NGINX request IDs.
- **Leakage discipline:** run-separated partitions and a strict numerical feature allowlist, while recognizing repeated-template leakage.
- **Unsupervised anomaly detection:** why high precision with low recall still misses dangerous events.
- **Baseline comparison:** the value of a simple rule-based reference and why perfect synthetic results should increase skepticism.
- **Engineering practices:** deterministic seeds, saved split manifest, failed-closed validation, unit and Docker integration tests, local-only API/data boundaries.
- **Next research question:** evaluate whether template-disjoint splits and benign authentication errors materially change detector rankings.

## Suggested concise project description

> CyberSentinel is a reproducible local security telemetry research prototype. I implemented/used a pipeline connecting NGINX access logs to trusted simulation labels, 60-second behavioral features, run-aware Isolation Forest evaluation, and a read-only FastAPI/Streamlit dashboard. Our controlled test exposed a substantial limitation: 29.17% attack recall and no scanning detections at the chosen threshold. The project emphasizes transparent metrics, leakage-aware evaluation, automated testing and security boundaries rather than unsupported production claims.

Adapt the first-person contribution statement above to reflect **your own confirmed contributions**, especially because this repository is collaborative.
