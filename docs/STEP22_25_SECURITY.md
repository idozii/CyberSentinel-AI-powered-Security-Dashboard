# Step 22-25 - Local MVP Security Notes

## Isolated boundary

- One FastAPI process on `127.0.0.1:8019` only; app opt-in and no reverse proxy.
- New runner refuses to start if common Neon or Auth0 secret environment variables are set.
- Keys start with `csd_` and are stored as one SHA-256 digest in process RAM.
- Issuing another key invalidates the previous key AND clears events/alerts.
- Session and form CSRF protections, Origin allow-list, and loopback middleware remain unchanged.
- Agent HTTP target is hardcoded to localhost with proxy/redirect protection in the existing client.
- The agent transforms raw IP addresses into daily HMAC pseudonyms; raw URLs, queries, bodies, cookies and User-Agent never leave the local input process.

## Triage evidence

- Filters accept a small allow-list of rule IDs, status and severity.
- Search is restricted to alert title and rule ID, bounded to 64 characters.
- Evidence shows pseudonymous source prefix and aggregate HTTP status/path categories only.
- Values are HTML escaped; unknown alert ID is 404; full agent key never appears in triage output.
- Acknowledgements continue using the existing CSRF-protected route.

## Limitations / unfinished work

- In-memory and single-tenant demonstration. Server restart erases credentials and events.
- No multi-user authentication, durable agent outbox, continuous daemon or remote delivery in this patch.
- No hardware-backed key protection, public TLS, external security review, load test or backup verification.
- Offline validation and 11 supplementary human-authored synthetic scenarios cannot establish real-world attack detection performance.
- `pyproject.toml` adds an optional demo console command; not a production binary/package distribution.
- This release is for portfolio presentation only, not a security control to rely on for protection.
