# CyberSentinel - Recruiter & Research Demo Pack

## Elevator pitch (30 seconds)

CyberSentinel is a reproducible, local-first security telemetry research project. It takes controlled NGINX HTTP events, connects them with simulation labels, builds behavioral features and evaluates both unsupervised Isolation Forest and explainable rules. It has a SOC-style Streamlit dashboard, read-only FastAPI APIs, optional local owner monitoring and a continuously tested security architecture. It is **not marketed as a production IDS**.

## Live demo route (3-4 minutes, no cloud accounts)

1. Start with `python -m scripts.zero_cost_portfolio audit`, pointing out 2,678 simulated requests and 160 windows.
2. Run `python -m scripts.zero_cost_portfolio demo` and open `http://127.0.0.1:8501`. No database, domain or Auth0 identity is needed.
3. Show the traffic and anomaly detection cards. Explain benign/attack simulations and how request-ID joins prevent silently assigning labels to unrelated events.
4. Show recall 29.17%, F1 0.4516 and 0/8 scanning detections. Explain why this is an important negative finding and why a fixed-rule baseline scoring 100% is likely an easy synthetic benchmark.
5. Show CI actions and mention disposable PostgreSQL RLS/JWT security proofs. Make clear these are proof-of-concept tests, **not live tenant-safe SaaS**.
6. Share the standalone HTML audit (generate with `audit --output /tmp/cybersentinel_evidence.html`) if live environment setup is unavailable.

## Resume lines (adapt to your actual contributions)

- Developed a reproducible NGINX-to-Python telemetry pipeline with synthetic request-ID labels, 14 behavioral window features and train/validation/test split by simulation run.
- Evaluated an Isolation Forest anomaly detector against rule-based baselines and documented weak recall (29.17% on 24 held-out simulated attack windows), including scanning failure modes.
- Built a local SOC visualization and security testing workflow with FastAPI, Streamlit, SQLite, Docker and GitHub Actions; validated tenant-bound PostgreSQL access patterns in disposable integration tests.

Do not imply you individually implemented every component without checking the repository's Git history and team contributions.

## What would make this publishable research?

Not the current metrics alone. A credible next paper would need a research question and baselines evaluated on a **new dataset**: template-disjoint attack families, natural benign error traffic, multiple seeds and confidence intervals, a detector calibrated using validation data only, and a locked final test set. Write negative outcomes as findings, not as product accuracy claims.

## GitHub release package

A release candidate should contain: exact commit SHA, passing CI URL, zero-cost install commands, deterministic evidence report, limitations, license/attribution checks, and only synthetic public metrics. Do not attach raw real-world logs, local SQLite databases, private tokens or unfrozen model pickles.
