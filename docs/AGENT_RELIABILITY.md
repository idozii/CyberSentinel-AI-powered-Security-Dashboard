# CyberSentinel - Agent Reliability Design (Step 13)

## Scope

A foreground localhost-only watcher collects NGINX JSONL, sanitizes each event using the existing Step 11 adapter, persists it in a bounded SQLite outbox, and retries delivery to the Step 12 API. This is a development prototype and NOT guaranteed exactly-once delivery, full log capture, or remote always-on monitoring.

## Source and trust boundaries

- Input path is a regular, non-symlink local file. Log entries are untrusted JSONL and must be newline terminated, smaller than 8 KiB, and valid under `to_minimal_event`.
- Before persistence, each event is reduced to a pseudonymous source reference, HMAC event ID, timestamp, method, path group, status, duration and byte counts. Raw identifiers and headers never enter SQLite.
- API target stays fixed at the existing `http://127.0.0.1:8002` loopback origin. HTTP redirect following and ambient HTTP proxy usage remain disabled by the Step 11 client.
- The SQLite state binds to the exact input path, domain ID and agent key fingerprint. Plaintext key is not saved.

## Atomicity and retry

Per complete line, the insert into `queue` and update of `cursors` happen in one transaction. This ensures a crash during processing cannot commit a cursor beyond an unrecorded sanitized event. SQLite uses `synchronous=FULL` and stores the database under owner-only permissions. The project does not make a guarantee against filesystem or storage hardware failure.

Pending batches contain at most 25 events. After a successful receipt where `accepted + duplicates = submitted`, the queue rows are removed. A crash after HTTP success but before removal can resend events; the Step 11 unique `(domain_id, agent_event_id)` constraint turns repeats into `duplicates`. Sending and acknowledgment are therefore **at least once while the source/outbox remain recoverable**, not exactly once.

A non-retryable HTTP 4xx response (excluding 429) stops the process and leaves the outbox. Network failures, 429, and 5xx use bounded exponential backoff. The output prints queue size and retry status without secret data.

## Log rotation and truncation

- On rename + recreate while the watcher runs, it keeps the old open file descriptor until complete lines are drained, then follows the new inode from byte 0.
- On restart, it tries to find the last known inode among up to 32 `access.log.*` files in the same directory.
- If that inode is unavailable, the watcher emits a `rotation_recovery_warning` and begins the new file from its first byte. Data lost before the restart may be unrecoverable.
- With copytruncate it resets to the start when current file length is less than the old offset. If the file is truncated and refilled past the previous size before the poll, truncation cannot be reliably detected.
- An incomplete final line is not advanced. A line that never gets a newline remains pending in the original file and may not be rescued after rotation.

These cases make the prototype *best effort* under rotation, not a lossless log shipping system. For hosted deployment, use a supervised agent and a log pipeline with tested rotation semantics, durable cursors and a dead-letter mechanism.

## Critical time boundary

The server rejects events beyond the 5-minute occurred_at window. Queues held past this limit cannot be sent under the existing API rules. The watcher never changes their timestamps or silently drops them. The operator can explicitly run `--purge-expired --confirm-loss`, after investigating the cause and accepting data loss. Freshness validation also prevents stale raw log lines from being ingested.

## Operational limits

| Property | Step 13 setting |
|---|---|
| Transport | Local HTTP on 127.0.0.1:8002 only |
| Client outbox | SQLite, maximum 1,000 sanitized events |
| Poll interval | Configurable 0.1 to 60 seconds, default 1 |
| Read cap | 100 complete log lines per poll |
| HTTP batch | 25 events maximum |
| API rate limit | 300 events per verified domain per minute |
| API freshness | 5 minutes |
| Retry | Exponential 2 to 60 seconds |
| Process lock | POSIX advisory file lock |
| Runtime files | Under ignored `simulations/runtime/owner/` |

## Recommended future work

Replace the local-only restrictions only after implementing an authenticated TLS ingress, managed identity, durable multi-tenant storage, message queues, proper logging/metrics and alerting for failed ingestion, privacy and retention policies, outage backfill strategy and load testing. As in earlier steps, the current lab Isolation Forest model is not production-ready for alert decisions.
