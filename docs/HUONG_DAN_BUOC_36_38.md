# CyberSentinel - Huong dan Buoc 36-38

Scope: PostgreSQL tenant isolation regression in ephemeral CI, privacy-safe local agent operational checks and private SQLite outbox backup/restore rehearsal. **Not a public deployment.** No domain or Neon credentials needed locally.

## Apply on top of merged Step 33-35

```bash
cd ~/Desktop/CyberSentinel-AI-powered-Security-Dashboard
git status
git switch main
git pull --ff-only origin main
git switch -c feat/tenant-ops-recovery-step36-38
unzip -o ~/Downloads/CyberSentinel_Buoc_36_38_Security_Recovery.zip -d .
python -m scripts.install_step36_38
source /home/idozii/envs/ds/bin/activate
```

## Step 36 - PostgreSQL tenant isolation

```bash
python -m unittest discover -s tests -p test_step36_tenant_pg.py -v
```

Without isolated test DSNs the PostgreSQL tests SKIP locally. GitHub CI provisions disposable PostgreSQL 17, runs migrations, creates test owners and proves cross-owner key, telemetry and alert operations are denied. DNS verification is simulated ONLY inside CI fixture; do not try to bypass real verification. These checks do not defend a leaked runtime Postgres password: the trusted backend currently sets `cs.actor_id` on a shared DB role, and arbitrary SQL via a compromised runtime credential could impersonate another actor. Resolve that design limitation before public beta.

## Step 37 - Local operational diagnostic

```bash
python -m scripts.step37_ops_report
python -m scripts.step37_ops_report --state simulations/runtime/owner/demo-step33.sqlite3
```

The second command requires an existing 0600 outbox. It prints only aggregate counts and freshness status - never tokens, URLs, raw client IPs, DSNs, filenames or event payloads. A stale or full queue returns nonzero status; resolve it rather than modifying event timestamps.

## Step 38 - Private agent SQLite backup/restore

**Stop the watcher first**, then make a private local directory:

```bash
mkdir -p -m 700 "$HOME/.local/share/cybersentinel-private-backups"
python -m scripts.step38_outbox_recovery --backup \
  --source simulations/runtime/owner/demo-step33.sqlite3 \
  --destination "$HOME/.local/share/cybersentinel-private-backups/step38-snapshot.sqlite3"
python -m scripts.step38_outbox_recovery --restore --confirm-restore \
  --source "$HOME/.local/share/cybersentinel-private-backups/step38-snapshot.sqlite3" \
  --destination "$HOME/.local/share/cybersentinel-private-backups/step38-restored.sqlite3"
python -m cybersentinel_agent.state_cli \
  --state "$HOME/.local/share/cybersentinel-private-backups/step38-restored.sqlite3"
```

Backup uses SQLite's consistent backup API. Source and target must be owner-only files (0600), backup directory 0700, destination must not already exist. Never overwrite a live agent state. Restore does not update your current running watcher: select the new state explicitly after stopping the previous process, using the SAME bound domain, key and log path. Otherwise binding validation correctly denies it. Old events may still be rejected by the 5-minute API freshness limit; do not rewrite timestamps.

Snapshots store pseudonymous event metadata and are **unencrypted**. Treat them as sensitive. Do not commit, upload or share them; for production, design encrypted, access-controlled, retention-limited backups. No Neon/Postgres backup or recovery is performed by this command.

## Verify all

```bash
python -m unittest discover -s tests -p test_step36_38_safety.py -v
python -m scripts.step36_38_preflight
python -m scripts.step36_38_release
python -m unittest discover -s tests -v
python -m scripts.step30_beta_gate --expect-blocked
python -m scripts.release_audit
python -m scripts.normalize_dashes --check
```

CI must PASS on new PR including dedicated PostgreSQL RLS job. Local skipped database tests are not equivalent to a PostgreSQL PASS.

## Commit and PR

```bash
git diff --check
git add .github/workflows/ci.yml README.md scripts/install_step36_38.py \
  tests/test_step36_tenant_pg.py tests/test_step36_38_safety.py \
  scripts/step37_ops_report.py scripts/step38_outbox_recovery.py \
  scripts/step36_38_preflight.py scripts/step36_38_release.py \
  docs/HUONG_DAN_BUOC_36_38.md docs/STEP36_38_SECURITY.md
git diff --cached --check
git diff --cached --stat
git commit -m "test: harden tenant isolation and add private outbox recovery checks"
git push -u origin feat/tenant-ops-recovery-step36-38
```

Open PR: https://github.com/idozii/CyberSentinel-AI-powered-Security-Dashboard/compare/main...feat/tenant-ops-recovery-step36-38?expand=1

## After merge

Focus next on architecture review of runtime PostgreSQL actor identity binding, real staging recovery drills, securely audited HTTPS ingress and consented beta trials. Existing Beta Gate should remain NO-GO until all evidence is independently reviewed.
