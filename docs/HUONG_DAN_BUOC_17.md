# CyberSentinel - Buoc 17: Private Auth0 Browser Login and Owner Domains

## Scope and verified prerequisites

Step 17 is an intentionally local-only browser pilot. It adds Auth0 Regular Web
Application Authorization Code + PKCE (S256), server-side code exchange, ID token
nonce verification, RS256 access token validation, HttpOnly in-memory session,
CSRF-protected domain forms, Neon/PostgreSQL owner data and DNS TXT proof.

**Step 16 is included in the combined ZIP** because GitHub `main` was still at
Step 15 when the ZIP was prepared. The Neon `cybersentinel_stage` database already
has migration 001 applied and checksum recorded, so do not recreate that database
or edit the 001 SQL file. The existing local SQLite lab remains unchanged.

**This is NOT public owner signup, public SaaS, a hosted security detector, or a
production session/authentication system.** PostgreSQL telemetry and alerts have
not been migrated. HTTP loopback cookies and in-process sessions must not be used
as public deployment configuration. This pilot runs one process, one worker,
on your own machine only.

## 17.1 Apply patch to GitHub main

```bash
cd /path/to/CyberSentinel-AI-powered-Security-Dashboard
git status
git switch main
git pull --ff-only origin main
git switch -c feat/hosted-auth0-browser-step16-17
unzip -o ~/Downloads/CyberSentinel_Buoc_17_Auth0_Browser_Combined.zip -d .
```

The ZIP includes Step 16 `hosted_api`, CI and scripts. If you have Step 16
uncommitted locally, preserve it before switching branches and inspect `git diff`.
Do not commit `.env`, SQL credentials, session cookies, Auth0 Client Secret,
access tokens or other runtime files.

## 17.2 Configure Auth0 Regular Web Application

Open Auth0 Dashboard > Applications > Applications > CyberSentinel Web > Settings.
The application type must be **Regular Web Application** with confidential
client credentials. Copy **Client ID** and **Client Secret** locally.

Set **Allowed Callback URLs** exactly to:

```
http://127.0.0.1:8007/auth/callback
```

Set **Allowed Logout URLs** (optional, future hosted Auth0 logout integration):

```
http://127.0.0.1:8007/
```

Click Save Changes. For Step 17, logout invalidates the local portal session;
it does **not** log the user out of the Auth0 SSO session. Explicitly signing out
of Auth0 globally is a separate operation.

The Auth0 API Identifier (audience) is:

```
https://cybersentinel.example/api
```

The Auth0 tenant is:

```
cybersentinel.au.auth0.com
```

Make sure your Auth0 API uses RS256 and has an enabled user login connection.
If the callback URL is rejected, verify that the Auth0 application really is a
Regular Web Application and check the tenant's localhost callback policy.
Do not substitute a live HTTPS URL: Step 17 is locked to the local callback.

## 17.3 Install dependencies

```bash
source /home/idozii/envs/ds/bin/activate
python -m pip install -r requirements-ml.txt -r requirements-dashboard.txt \
  -r requirements-owner.txt -r requirements-hosted.txt
python -m pip install -e .
```

## 17.4 Configure secrets in zsh

Since your shell is zsh, do not use Bash `read -rsp`.
For Auth0 Client ID (not secret), use:

```bash
export CYBERSENTINEL_OIDC_ISSUER="https://cybersentinel.au.auth0.com/"
export CYBERSENTINEL_OIDC_AUDIENCE="https://cybersentinel.example/api"
export CYBERSENTINEL_OIDC_JWKS_URL="https://cybersentinel.au.auth0.com/.well-known/jwks.json"
export CYBERSENTINEL_AUTH0_CALLBACK_URL="http://127.0.0.1:8007/auth/callback"
export CYBERSENTINEL_AUTH0_CLIENT_ID="PASTE_AUTH0_WEB_CLIENT_ID"
```

Then enter the secrets without terminal echo:

```bash
printf 'Auth0 Web Client Secret: '
IFS= read -rs CYBERSENTINEL_AUTH0_CLIENT_SECRET
printf '\n'
export CYBERSENTINEL_AUTH0_CLIENT_SECRET

printf 'Neon runtime PostgreSQL DSN: '
IFS= read -rs CYBERSENTINEL_PG_RUNTIME_DSN
printf '\n'
export CYBERSENTINEL_PG_RUNTIME_DSN
```

The runtime DSN MUST use the `cybersentinel_runtime` user with a password,
TLS `sslmode=require`, and database `cybersentinel_stage`.
Never print DSNs, tokens or secrets or paste them into ChatGPT.

## 17.5 Check migrations and tests

The Neon database already has migration 001, including a checksum.
The migration should now respond `already-applied` if an admin DSN is provided.
Do not put the privileged migration DSN into the portal environment.

```bash
python -m unittest discover -s tests -v
python -m scripts.release_audit
python -m scripts.step14_preflight
python -m scripts.step15_preflight
python -m scripts.step16_preflight
python -m scripts.step17_preflight
python -m scripts.normalize_dashes --check
```

Five Step 16 PostgreSQL tests are skipped without dedicated CI test DSNs.
They run against PostgreSQL 17 within a dedicated GitHub Actions job.
Never aim tests at a database containing real customer data.

## 17.6 Start Auth0 browser portal

```bash
uvicorn hosted_api.web:factory --factory --host 127.0.0.1 --port 8007 --workers 1
```

Open `http://127.0.0.1:8007/`, click **Sign in with Auth0**, sign in using
Auth0 Universal Login, and you will return to `http://127.0.0.1:8007/domains`.
This is different from the Step 16 access-token API on port 8006; both
work independently against the same PostgreSQL schema.

Add a DNS hostname you own, copy the TXT record name/value from the one-time
creation page, publish that TXT record using your DNS provider, then use
**Verify DNS** after it has propagated.

To check the staging health endpoint:

```bash
curl -fsS http://127.0.0.1:8007/health
```

A browser login test with a real Auth0 user is manual, not fully covered by CI.
If you get `Callback URL mismatch`, the Auth0 Allowed Callback URLs value must
match exactly, including `http`, numeric loopback address, port and path.

## 17.7 Review and merge

```bash
git add README.md .github/workflows/ci.yml requirements-hosted.txt \
  hosted_api/ scripts/step16_migrate.py scripts/step16_preflight.py \
  scripts/step17_preflight.py scripts/release_audit.py \
  tests/test_step16_hosted.py tests/test_step16_postgres.py \
  tests/test_step17_browser.py docs/HUONG_DAN_BUOC_16.md \
  docs/STEP16_DATABASE_IDENTITY_SECURITY.md docs/HUONG_DAN_BUOC_17.md \
  docs/STEP17_BROWSER_SECURITY.md

git diff --cached --check
git diff --cached --stat
python -m scripts.normalize_dashes --check
python -m scripts.release_audit
git commit -m "feat: add Neon OIDC foundation and private Auth0 browser portal"
git push -u origin feat/hosted-auth0-browser-step16-17
```

Create a PR into `main`. CI must show all four jobs green, including **real
PostgreSQL 17 RLS**. Never commit credentials or publish the private portal.

## Next steps

Step 18 should migrate telemetry, agent keys and alerts from the SQLite
prototype into PostgreSQL with owner-scoped RLS and controlled data migration,
then build a separate HTTPS public-beta design with distributed sessions,
logout/revocation strategy, public abuse controls and real deployment review.
