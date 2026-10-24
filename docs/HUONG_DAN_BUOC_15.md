# CyberSentinel - Buoc 15: Private Owner Portal and Data Safety

## 1. What this step does

Step 15 adds a staging operations layer to the Step 14 isolated HTTPS ingest bridge:

- A private Streamlit Owner Portal service bound to 127.0.0.1:8503.
- SSH tunnel access for a trusted operator. No publicly reachable owner registration or login.
- Consistent online SQLite backups using the built-in SQLite backup API.
- Restore drills in a temporary directory without overwriting the live database.
- Data retention: old events, old alerts, expired sessions and expired pending DNS challenges.
- systemd service/timer templates, 17 regression tests and a static configuration preflight.

All new text uses ASCII hyphens. Do not replace CLI `--` flags.

**Step 15 is NOT production SaaS.** Owner registration, emails, authentication and telemetry remain in a single-host SQLite prototype. Hosted accounts and PostgreSQL migration are later milestones. No VPS or DNS has been configured by this source bundle.

## 2. Branch and install

Work in the repository root. Ensure the previous branch is clean.

```bash
git status
git switch main
git pull --ff-only origin main
git switch -c feat/private-owner-operations-step15
unzip -o ~/Downloads/CyberSentinel_Buoc_15_Private_Ops.zip -d .
source .venv/bin/activate
python -m pip install -r requirements-ml.txt -r requirements-dashboard.txt -r requirements-owner.txt
python -m pip install -e .
python -m unittest discover -s tests -v
python -m scripts.release_audit
python -m scripts.normalize_dashes --check
python -m scripts.step14_preflight
python -m scripts.step15_preflight
```

Expected on a complete Step 14 checkout: 183 existing tests + 17 new tests = 200 tests. CI still runs Python 3.12, Python 3.13 and Docker smoke. Do not merge a failing PR.

## 3. Test SQLite safely on your local machine

The Owner API initializes the local database when launched. If you have not started Step 10-14 before, run it locally:

```bash
uvicorn owner_api.main:app --host 127.0.0.1 --port 8002
```

From another terminal with the same venv and from the repo root:

```bash
python -m scripts.step15_ops inspect
python -m scripts.step15_ops retention
python -m scripts.step15_ops backup
```

`retention` without `--apply` is a dry run. It reports eligible row counts without changing anything. `backup` creates a new SQLite file with restrictive filesystem permissions under `simulations/runtime/owner/backups/`. This location is ignored by Git.

The backup command prints a `backup_path`. Copy the exact output path into the next command:

```bash
python -m scripts.step15_ops restore-check --backup-file /full/path/to/owner-backup-XXXX.sqlite3
```

`restore-check` only restores to a temporary directory and checks schema, data integrity and foreign keys. It NEVER replaces the active SQLite database. Never share the backup file, screenshots containing credentials, or raw telemetry.

When ready to apply the seven-day retention policy:

```bash
python -m scripts.step15_ops retention --apply
```

Take a verified backup first. The cleanup preserves user accounts, verified domains, agent keys and recent alerts/events. It removes expired sessions, events older than seven days by receipt time, alerts older than seven days by their event window, and clears expired TXT challenges on unverified domains. These deletions cannot be undone except from a pre-cleanup backup.

## 4. Configure a PRIVATE VPS staging portal

Only do this on a VPS you administer. The Step 14 ingest endpoint can be reached over HTTPS; the Owner API and Streamlit portal must remain on loopback. Deploy application source to `/opt/cybersentinel/app`, with venv `/opt/cybersentinel/venv`, service account `cybersentinel`, and private DB directory `/var/lib/cybersentinel`.

Create and protect the database and backup folders as an administrator:

```bash
sudo install -d -o cybersentinel -g cybersentinel -m 0700 /var/lib/cybersentinel
sudo install -d -o cybersentinel -g cybersentinel -m 0700 /var/lib/cybersentinel/backups
```

On your VPS, copy these example files after inspecting their paths and service user:

```bash
sudo cp deploy/cybersentinel-portal.service.example /etc/systemd/system/cybersentinel-portal.service
sudo cp deploy/cybersentinel-backup.service.example /etc/systemd/system/cybersentinel-backup.service
sudo cp deploy/cybersentinel-backup.timer.example /etc/systemd/system/cybersentinel-backup.timer
sudo cp deploy/cybersentinel-retention.service.example /etc/systemd/system/cybersentinel-retention.service
sudo cp deploy/cybersentinel-retention.timer.example /etc/systemd/system/cybersentinel-retention.timer
sudo systemctl daemon-reload
sudo systemctl enable --now cybersentinel-portal.service
sudo systemctl enable --now cybersentinel-backup.timer
sudo systemctl enable --now cybersentinel-retention.timer
```

The Step 14 private Owner API systemd service must already be configured and running on `127.0.0.1:8002`. Check firewall rules: ports 8002, 8004 and 8503 must NOT accept public connections. Do not add owner routes to the public Caddyfile. Check `systemctl status` and `journalctl -u ...` for errors; the timers do not independently guarantee backup success.

From your own workstation, not the VPS, open an SSH tunnel:

```bash
ssh -N -L 8503:127.0.0.1:8503 your-admin-user@YOUR_VPS_HOST
```

Open `http://127.0.0.1:8503` on your workstation. Do not make this an unauthenticated public website. This tunnel requires trusted SSH authentication; it does not replace production customer identity infrastructure.

Before depending on staging backups, run one backup service manually and verify a restore drill, monitoring disk capacity and file permissions:

```bash
sudo systemctl start cybersentinel-backup.service
sudo systemctl status cybersentinel-backup.service
sudo journalctl -u cybersentinel-backup.service --since today
```

Backups hold real owner data. Encrypt them before sending off-host, restrict operator access and set an explicit backup retention policy. Step 15 deliberately does not implement automatic cloud uploads, encryption, rollback automation or a PostgreSQL datastore.

## 5. Review Git changes and create PR

```bash
git add README.md .github/workflows/ci.yml scripts/release_audit.py \
  owner_api/operations.py scripts/step15_ops.py scripts/step15_preflight.py \
  tests/test_step15_operations.py docs/HUONG_DAN_BUOC_15.md \
  docs/STEP15_OPERATIONS_SECURITY.md deploy/cybersentinel-portal.service.example \
  deploy/cybersentinel-backup.service.example deploy/cybersentinel-backup.timer.example \
  deploy/cybersentinel-retention.service.example deploy/cybersentinel-retention.timer.example

git diff --cached --check
git diff --cached --stat
git status --short
python -m scripts.normalize_dashes --check
python -m scripts.release_audit

git commit -m "feat: add private owner staging operations and SQLite backup drills"
git push -u origin feat/private-owner-operations-step15
```

Create a PR targeting `main`. Merge only after GitHub Actions jobs pass.

## 6. Next milestone

Step 16 is a real PostgreSQL migration and a managed identity architecture. Only after multi-tenant isolation, audit logs, abuse controls, email verification, stronger account lifecycle and security review should owner login and public registration be exposed to the Internet. Step 15 is an operator-only, private staging milestone.
