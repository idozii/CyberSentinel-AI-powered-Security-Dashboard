# CyberSentinel - Local Agent Trust Boundaries

## Which audience can do what?

- Public visitors can run Step 9 HTTPS posture checks but cannot access owners' events.
- An owner who passes DNS TXT challenge obtains an owner session for key management and reading recent events.
- An agent obtains a separate, scoped key for **one** verified domain. An agent key cannot register, claim domains, create other keys, or list events.
- All three surfaces remain separate. This Step 11 backend must not be exposed to the public Internet.

## Data minimization

The adapter reads NGINX access log JSON locally and sends only:

`event_id`, `occurred_at`, `source_ref`, `method`, `path_group`, `status_code`, `duration_ms`, `request_bytes`, `response_bytes`.

The `source_ref` is HMAC-SHA256 truncated to 16 bytes, computed from source IP, UTC day and the per-domain agent key. It permits limited within-day grouping without transmitting raw IP. An HMAC pseudonym is still potentially personal data; protect and delete it appropriately. It changes if the key or day changes.

Important: this is not full anonymization. Local NGINX logs continue to contain sensitive details and must be safeguarded by the owner. Never upload raw logs, model pickle/joblib files or keys to a public cloud service.

## Local ingestion controls

- Authorized owner session, verified domain, scoped agent key and one-time plaintext issue.
- SHA-256 digest storage for high-entropy random agent tokens; cleartext key never saved.
- Atomic SQLite writes, unique domain/event IDs, idempotent replay, domain-owned reads and cascaded deletion.
- Body <= 32 KiB, 1..25 events, time skew <= 300 seconds, domain quota <= 300 events/minute, limited public response fields.
- Strict event allowlist rejects unexpected raw fields. Key list and recent read are owner-authenticated.
- The Python agent only sends to `http://127.0.0.1:8002`, with no redirect or proxy environment support.

## Before deploying on the Internet

The current solution lacks managed authentication, secure HTTPS edge, per-tenant durable database, distributed rate limiting, ingestion backpressure, privacy consent workflow, log rotation handling, sustained agent retries, enterprise tenant permissions, abuse monitoring, and independent security review.

Do not change the loopback restriction merely to demonstrate a 'live' website. A public real-time monitoring service requires a separate production architecture and external penetration/security review.
