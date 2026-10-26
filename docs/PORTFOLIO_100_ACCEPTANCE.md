# CyberSentinel - 100% Portfolio Acceptance Checklist

**Scope:** a zero-subscription student portfolio for AI/Data Science/cybersecurity internship interviews. It is *not* a 100% accurate detector, a production IDS, or an internet-facing multi-tenant SaaS.

## A. Automated release validation

Run from a fresh Git clone in a clean Python 3.12 or 3.13 environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-ml.txt -r requirements-dashboard.txt -r requirements-owner.txt -r requirements-hosted.txt
python -m pip install -e .
python -m unittest discover -s tests -v
python -m scripts.release_audit
python -m scripts.normalize_dashes --check
python -m scripts.zero_cost_portfolio audit
python -m scripts.zero_cost_portfolio audit --full
python -m scripts.portfolio_finalizer
python -m scripts.portfolio_finalizer --output-dir /tmp/cybersentinel-final-HANDOFF
```

Use a new directory name if `/tmp/cybersentinel-final-HANDOFF` already exists. No Neon, Auth0, paid hosting or production tenant data required. The full unit suite may deliberately SKIP tests requiring GitHub Actions disposable PostgreSQL; verify those separately on GitHub CI.

## B. Visual review (human tasks - cannot be auto-attested)

- [ ] Start `python -m scripts.zero_cost_portfolio demo` and open http://127.0.0.1:8501; verify from a fresh browser profile.
- [ ] Capture **real** screenshots, not generated mock-ups: Overview, Traffic & features, Model evaluation, Architecture. Save scrubbed images under `docs/images/` (do not upload private tokens, personal accounts or raw request logs).
- [ ] Capture a 2-4 minute walkthrough. Show architecture, actual synthetic dataset size, failure modes, CI evidence and how the demo is started without credentials.
- [ ] Ensure the public Streamlit deployment (if used) opens without local dependencies and clearly labels *synthetic, not live monitoring*. Test the link in a new incognito browser.
- [ ] Ask a reviewer to follow the clean-clone setup and record their results.

## C. Research quality and honesty

- [ ] State that the recorded 2026-10-24 evaluation is **user-reported**; raw output files are not committed.
- [ ] Display Isolation Forest test TP 7, FN 17, recall 29.17%, with scanning recall 0/8.
- [ ] Identify high attack prevalence (24/32 test windows), repeated attack templates and eight benign holdout windows as serious limitations.
- [ ] Never describe 100% rule baseline performance on this lab as general real-world effectiveness.
- [ ] If making a *new* research claim, create a new template-disjoint, diverse-benign test set and freeze all thresholds before inspecting its results. Do not retrofit a successful result or overwrite the existing benchmark.

## D. Public release and attribution

- [ ] GitHub Actions checks PASS for **final commit**: Python 3.12/3.13, Docker, NGINX smoke and disposable PostgreSQL.
- [ ] `README.md` points to clean-clone, demo, report, limitations and release guides.
- [ ] Verify existing MIT `LICENSE` and the team's permission / individual-contribution attribution.
- [ ] GitHub release tag created from verified `main` commit (do not reuse an existing tag).
- [ ] Release notes link exact CI run and contain no runtime SQLite DBs, real traffic logs, `.env`, tokens or serialized private models.
- [ ] Check README, public dashboard, source, screenshots, demo video and release URLs manually after publication.

## E. Interview-ready evidence

- [ ] Present the data pipeline and where labels originated (simulation manifest, not a perfect ground truth).
- [ ] Explain why group/run splits do not remove repeated-template leakage.
- [ ] Explain why unsupervised model recall is weak and how to design an independent benchmark.
- [ ] Explain FastAPI, Streamlit, SQLite, Docker and GitHub Actions boundaries.
- [ ] Distinguish the disposable PostgreSQL tenant proof from live staging's shared-role risk and unshipped SaaS features.
- [ ] Make every CV claim consistent with specific Git history and the team contribution agreement.

## Readiness decision

- **Automated PASS:** source, evidence and documented checks pass; all manual tasks remain pending until verified.
- **Portfolio presentation 100%:** all A-E checks, external links and real user demonstration reviewed by a human, and final CI PASS. This is a *process definition*, not a scientific/production security certification.
- **Public SaaS:** NO-GO regardless of the portfolio outcome.

Stop adding CI-only security prototypes merely to increase step numbers. Prioritize truthful research explanation, reproducibility, usability and recruiter presentation.
