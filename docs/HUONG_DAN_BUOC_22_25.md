# CyberSentinel - Huong dan Fast-track Buoc 22-25

Gop 4 buoc thanh 1 pull request. Chi demo localhost, KHONG can domain, Auth0, Neon, public hosting hay migration.

## Buoc 0 - an toan Git

Dam bao PR #23 (Buoc 21) da merge, `git status` sach, dang o root repository:

```bash
git switch main
git pull --ff-only origin main
git switch -c feat/local-portfolio-mvp-step22-25
unzip -o ~/Downloads/CyberSentinel_Buoc_22_25_FastTrack.zip -d .
source /home/idozii/envs/ds/bin/activate
python -m pip install -r requirements-owner.txt -r requirements-hosted.txt -r requirements-dashboard.txt
python -m pip install -e .
python -m unittest discover -s tests -p test_step22_25_fasttrack.py -v
python -m scripts.step25_preflight
python -m scripts.step25_release
```

## Buoc 22 - Alert triage

Chay demo tu mot terminal KHONG chua DSN / Auth0 Client Secret:

```bash
python -m scripts.step25_demo
```

Mo `http://127.0.0.1:8019/`. Generate new local demo key; luu `csd_` key an toan. Mo `http://127.0.0.1:8019/demo/alerts` de loc severity/status/rule, va xem evidence tu tung alert. Khong bao gio dua key vao screenshots.

## Buoc 23 - Agent one-shot va key lifecycle

Trong terminal khac:

```bash
source /home/idozii/envs/ds/bin/activate
printf 'Demo key: '
IFS= read -rs CYBERSENTINEL_AGENT_KEY
printf '\n'
export CYBERSENTINEL_AGENT_KEY

python -m scripts.step19_generate_logs --scenario login --output /tmp/cs-login-unique.jsonl
python -m scripts.step23_agent_doctor --check-server --input /tmp/cs-login-unique.jsonl

cybersentinel-demo-agent --input /tmp/cs-login-unique.jsonl --domain-id DEMO_DOMAIN_ID --dry-run
cybersentinel-demo-agent --input /tmp/cs-login-unique.jsonl --domain-id DEMO_DOMAIN_ID
```

Use your actual Demo Domain ID from dashboard, not placeholder. `cybersentinel-demo-agent` is installed with `pip install -e .`. It can send up to 100 validated log events in batches of 25. To test 40 request spike, generate `traffic` and run same CLI with the new file name.

Replay the SAME JSONL within 5 minutes: `accepted=0`, `duplicates` equals number of events. Issue a new local demo key to rotate. **Rotation clears all demo data**, and old `csd_` keys are no longer authorized. There is no on-disk outbox in this one-shot demo; if interrupted mid-send, retry the exact same file while events are fresh.

Never use `csp_` or `csa_` keys against localhost demo; do not send `csd_` to staging.

## Buoc 24 - Supplemental robustness test

```bash
python -m scripts.step24_failure_analysis
python -m scripts.step24_failure_analysis --output-dir /tmp/cs-step24-report-unique
```

This adds 11 manually labeled synthetic scenarios without changing the frozen Step 20/21 baseline. The benchmark demonstrates false alarms and misses, not real attack detection accuracy. The optional output directory must not exist and must be outside the repository.

## Buoc 25 - Local portfolio release

```bash
python -m unittest discover -s tests -v
python -m scripts.step21_quality_gate
python -m scripts.step25_preflight
python -m scripts.step25_release
python -m scripts.release_audit
python -m scripts.normalize_dashes --check
```

All checks must pass. PostgreSQL integration tests may skip locally; GitHub CI PostgreSQL 17 job must pass before merge. No new SQL migration or public hosting is included.

## Commit / pull request

Review `git status` and `git diff --check`. Stage only the files in this patch, NOT `.env`, DSNs, tokens, simulation logs, or private credentials. Suggested command:

```bash
git add .github/workflows/ci.yml README.md pyproject.toml \
  hosted_api/local_demo.py hosted_api/demo_triage.py \
  cybersentinel_agent/demo_cli.py \
  scripts/step23_agent_doctor.py scripts/step24_failure_analysis.py \
  scripts/step25_demo.py scripts/step25_release.py scripts/step25_preflight.py \
  tests/test_step22_25_fasttrack.py \
  docs/HUONG_DAN_BUOC_22_25.md docs/STEP22_25_SECURITY.md \
  docs/LOCAL_MVP_RELEASE.md docs/ROADMAP_TO_PRODUCT.md
git diff --cached --check
git diff --cached --stat
git commit -m "feat: deliver isolated local portfolio MVP fast-track steps 22-25"
git push -u origin feat/local-portfolio-mvp-step22-25
```

Then open a pull request against main and wait for all CI jobs. The patch contains no credentials and makes no changes to Auth0/Neon schema.
