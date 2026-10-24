# Step 19 - Security boundaries of the localhost demo

## Goal

A deliberately untrusted, disposable training environment. Not a DNS
verification bypass, public multi-tenant product or hosted security service.

## Explicit isolation

- `CYBERSENTINEL_LOCAL_DEMO=1` is required; factory refuses startup otherwise.
- Only `http://127.0.0.1:8019`, a separate FastAPI app. TrustedHost and
  loopback client restrictions; start with `--host 127.0.0.1 --workers 1`.
- No import or invocation of Postgres/Neon DSN, Auth0 code exchange, real
  owner identities, actual DNS verifier, migration scripts, or prior SQLite
  databases. State is a process-memory `DemoStore` with a single fake UUID.
- `csd_` local key is generated with `secrets`, shown once, stored only as
  SHA-256 hex digest in RAM, and compared with constant-time comparison.
- The existing agent validates loopback port 8019 and enforces `csd_` only
  for demo. It explicitly rejects demo keys on staging and legacy APIs.
- POST actions are protected by a browser-generated CSRF value, strict
  SameSite cookie, HTTP-only cookie and Origin check. No browser login is
  offered - local physical access is assumed as the trust boundary.

## Data integrity and minimization

- Only a strict, minimal schema may be ingested: event ID, timestamp,
  pseudonymous source, method, path group, status and byte/duration totals.
  No raw source IP, URL/query, authentication secrets or User-Agent in the API.
- Synthetic NGINX generator uses documentation IPv4 192.0.2.44 only; the
  existing agent hashes client reference with an HMAC before delivery.
- Time range +/- 5 min; at most 25 events/batch, 120 *new* events/min and
  500 events per demo process; rate / capacity rejection occurs before writes.
- Batch deduplication by event ID and explainable 60s threshold rules.
- Server-side HTML escapes variable fields and rejects unexpected properties.
- Reset means issuing a new local demo key; old keys immediately stop working.
- Events, alerts and keys vanish on process restart; no export, backup or
  long-term retention promise.

## Known limitations

- No authenticated browser user and no RLS/multi-tenant isolation inside demo.
  Any other process or person with access to the same localhost environment
  can interact with the demo UI and generate new keys.
- A reverse proxy, public container binding, cloud hosting or port forwarding
  would invalidate the trust model; not supported.
- SHA-256 storage is for random high-entropy bearer tokens, not user
  passwords. Local demo keys are not valid production credentials.
- `Content-Length` limits, memory cap and input validation are not a
  replacement for a production firewall, DoS controls or security audit.
- CI tests simulate local ingest; a manual NGINX adapter -> HTTP path demo
  is described in `HUONG_DAN_BUOC_19.md`.
- Existing Postgres RLS and DNS ownership protections are deliberately
  unchanged. A request to bypass them for production must be rejected.

## HTML form Origin compatibility

Demo HTML uses `Referrer-Policy: same-origin` rather than `no-referrer`.
Under `no-referrer`, browsers can send `Origin: null` for same-origin
form POST navigation, which would be rejected by the strict form guard.
The policy change preserves the exact-origin check, CSRF hidden field,
SameSite and HttpOnly cookie protections and loopback-only binding.
Never accept arbitrary or `null` form origins to work around this issue.
