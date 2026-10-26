# CyberSentinel - Evidence-Based Completion Assessment (26 October 2026)

## Completion is objective-dependent

The following scores are **qualitative engineering estimates** and not a formal rubric, audit, compliance statement or mathematical project completion percentage. They use current source, CI evidence, reported evaluation metrics and explicitly missing capabilities.

| Goal | Estimated completion | Evidence and major gap |
|---|---:|---|
| AI/Data Science internship portfolio | 85% | Code, transparent experiment report, synthetic-to-model pipeline, public Streamlit presentation, strong CI. Improve a reproducible one-command demo, screenshots, concise CV story and reproducible independent evaluation. |
| Local SOC research MVP | 78% | Read-only local API, Streamlit explorer, local SQLite owner onboarding, scoped agent keys, dedup/alerts and durable watcher. No continuous deployment, fault-tolerant operational SOC or live production detections. |
| Novel/generalizable AI cybersecurity research | 58% | Isolation Forest vs fixed-rule evaluation, run-separated splits, 14 features and robustness. Needs independent realistic holdout, diverse benign errors, template-disjoint splits and uncertainty/repeated-seed results. |
| Public multi-tenant SaaS | 28% | Disposable PostgreSQL 17 role-isolation and HTTP+JWT proofs PASS CI, but the live staging store remains shared-role actor GUC. No production broker, vetted vault, external penetration review, deployment recovery guarantees or approval for public tenant traffic. |

These percentages are NOT additive. **For a student portfolio without ongoing hosting budget, the project is already close to a credible presentation-ready release.** For a commercial cybersecurity service, it is an early prototype.

## Recorded scientific result and caveat

The committed public experiment summary (2026-10-24) reports 2,678 labeled simulated requests, 160 feature windows, and 32 held-out windows (24 attack + 8 benign). Isolation Forest identified 7/24 attack windows (29.17% recall; 0.4516 F1) with 17 false negatives, including 0/8 path-scanning detections. Rule baseline recall was 100% on the same simplified synthetic test. Fixed repeated attack scripts, limited benign errors and small benign validation count mean there is **no demonstrated real-world detection accuracy** or publishable novel finding by itself.

## Milestone outcome with a 0 AUD/month managed-service budget

- Publish the static SOC research narrative using free code hosting and optionally free Streamlit Community Cloud; keep all research aggregate metrics versioned in Git. Local execution works without account signup, Neon/Auth0 or DNS purchases.
- Reproduce traffic generation, ML experiments, owner backend and alerting locally on-demand with Docker/Python/SQLite. Do not pretend an on-demand machine is a 24/7 service.
- Keep disposable PostgreSQL security tests in GitHub Actions if available; they do not require a hosted database.
- Retain but **do not depend on** Neon/Auth0 Free plans. Both advertise free tiers, subject to provider limits and product changes. The project should remain usable if the user never creates such accounts.
- Never publish a local owner API or CI-only synthetic tenant API as an internet-facing product. Preserve current NO-GO public beta gate.

## Ranked next improvements

1. **Recruiter-ready delivery (highest immediate value):** test a fresh clone, demonstrate local dashboard and evidence report, capture a clean 3-minute video, add GitHub release and 3-4 screenshots with no private data.
2. **Research validity:** one deliberately hard independent dataset or template-disjoint holdout, benign login mistakes and 404s, threshold sweeps on validation only, multi-seed confidence intervals, report that admits failures.
3. **Reliability:** real (consented) sample capture in a private local environment, idempotent replay/retry tests, resource and CPU/memory profiling, backup restore.
4. **Optional future SaaS:** reviewed tenant provisioning, managed secret custody, separate principal per tenant, full `cs.*` migration, external security audit, load tests, privacy and incident-response review. Funding/free quotas alone do not solve authorization and operational safety.

## Suggested CV positioning

"CyberSentinel - Reproducible Cybersecurity Telemetry & ML Research Platform (Python, NGINX, FastAPI, Streamlit, SQLite, PostgreSQL, scikit-learn, GitHub Actions). Built/tested a simulated-log ETL and anomaly-detection pipeline with run-aware evaluation, read-only SOC visualizations, and automated isolation/security regression tests. Documented the limitation of 29.17% attack recall on the synthetic holdout instead of overstating model performance."

Adapt the first-person contribution statement to your actual individual work in this multi-contributor repository.
