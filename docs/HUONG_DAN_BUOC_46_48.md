# CyberSentinel - Steps 46-48 Fast Track

This package adds new files only and uses a safe installer to append two CI steps. It does not overwrite the existing `.github/workflows/ci.yml`, modify existing migrations, or access Neon/Auth0.

## 1. Start from current main (PR #34 merged)

```bash
cd ~/Desktop/CyberSentinel-AI-powered-Security-Dashboard
git status
git switch main
git pull --ff-only origin main
git switch -c feat/step46-48-isolated-schema-rehearsal
unzip -o ~/Downloads/CyberSentinel_Steps46_48_FastTrack.zip -d .
source /home/idozii/envs/ds/bin/activate
```

If the working tree is not clean, save the changes before switching. The ZIP contains eight new files under `scripts/`, `tests/` and `docs/`.

## 2. Install CI checks safely

```bash
python -m scripts.install_step46_48 --check-only
python -m scripts.install_step46_48
python -m scripts.install_step46_48 --check-only
```

The installer requires exact anchors and the existing Step 44-45 CI registrations. If the workflow changed, the installer fails closed; review changes manually rather than overwriting.

## 3. Offline tests and security review

```bash
python -m unittest discover -s tests -p 'test_step46_48_offline.py' -v
python -m scripts.step48_release_gate
python -m compileall -q scripts tests
python -m unittest discover -s tests -v
python -m scripts.normalize_dashes --check
git diff --check
git status
```

Important: local PostgreSQL tests will normally be SKIPPED. That is correct and does not constitute a PostgreSQL pass. The release gate must report `public_beta_allowed: false`.

## 4. Commit and PR

```bash
git add .github/workflows/ci.yml \
  scripts/step46_trusted_binding.py \
  scripts/step47_schema_rehearsal.py \
  scripts/step48_release_gate.py \
  scripts/install_step46_48.py \
  tests/test_step46_48_offline.py \
  tests/test_step46_48_pg.py \
  docs/STEP46_48_SECURITY.md \
  docs/HUONG_DAN_BUOC_46_48.md

git diff --cached --check
git commit -m 'test: rehearse five-table tenant RLS and rollback in isolated CI'
git push -u origin feat/step46-48-isolated-schema-rehearsal
```

Use the GitHub PR page to open a PR from this feature branch to main.

## 5. Security merge gate

- Wait for the whole GitHub Actions workflow to complete successfully.
- Confirm `Steps 46-48 isolated cs schema migration and rollback proof` shows PASS (not SKIPPED).
- Confirm `Steps 46-48 identity binding, migration and rollback design` PASS on Python 3.12 and 3.13.
- Confirm original Step 41-45, NGINX and Docker jobs remain green.
- Only merge after tests pass and PR diff is reviewed.
- Even after merge, do not deploy this proof code to Neon or public access.
