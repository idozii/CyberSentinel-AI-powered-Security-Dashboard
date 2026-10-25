# Steps 33-35: Durable delivery security and recovery limitations

## Guarantees demonstrated by the synthetic integration tests

- Existing SQLite cursor/queue transaction is reused, not redesigned.
- Only minimal, validated event dictionaries enter the outbox, never raw NGINX lines.
- Protocol credentials are bound by destination: `csa_` (8002), `csd_` (8019),
  `csp_` (8008 or explicitly approved TLS DNS origin). Existing `csa_` HTTPS staging
  bridge support is preserved for Step 14. Client-side shape validation
  is *not* server authorization; the server must still verify the key hash and domain.
- After a simulated server receipt is lost, restart retries the same event ID;
  server deduplication yields no second alert.
- The status command requires a private SQLite state and opens it read-only.
- No changes to Auth0, Neon database, RLS, DNS verification, CSP or remote listeners.

## Critical known limitations

1. **Not a durable production telemetry service.** The SQLite outbox is a local
   bounded queue. It does not provide a high-availability agent, remote supervision
   or disk failure recovery.
2. **Five-minute TTL remains.** The local and staging APIs validate original event
   timestamps to within five minutes of current time. Queued events older than
   this cannot be recovered by automatic retry. The sender never forges a newer
   timestamp. A longer-outage recovery design requires a separately reviewed
   authenticated replay protocol with bounded retention and replay protection.
3. **Key rotation is manual.** The persisted cursor/outbox is pinned to key/domain/log
   and must never be carried silently into a new identity. Use a separate private
   state file for new keys and follow a documented cutover process.
4. **Ingest is at-least-once, not exactly-once.** A lost receipt leads to replay
   and relies on server deduplication.
5. **Rate limits/capacity differ.** Local Demo caps total in-memory events at 500
   and accepts up to 120 per minute; staging has different limits. High-volume
   sustained traffic needs an independently reviewed capacity plan.
6. **Only controlled test traffic.** Do not ship real logs or user data to the
   synthetic demo. Production privacy, consent, security review and monitoring
   are not approved. Beta Go/No-Go remains blocked.
