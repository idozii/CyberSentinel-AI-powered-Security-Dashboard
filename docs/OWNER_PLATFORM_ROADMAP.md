# CyberSentinel — Product Architecture and Owner Roadmap

## Two user journeys, one brand

1. **General visitors**: Public Streamlit website checks observable HTTPS configuration without credentials. Static research-showcase metrics are separate from live header checks.
2. **Website owners**: After account creation and DNS TXT verification, users can connect a future agent; this should eventually become a dedicated HTTPS web application and auth service rather than sharing the public Streamlit runtime.

## Product components and boundaries

```mermaid
flowchart TD
    V[Public visitor] --> C[Public HTTPS posture checker / Step 9]
    O[Website owner] --> P[Owner portal - localhost / Step 10]
    P --> A[Owner API: registration, bearer sessions]
    A --> D[(SQLite for local development)]
    A --> TXT[DNS TXT verifier]
    D --> G{Domain verified?}
    G -->|Future Step 11 only| KEY[Scoped agent key provisioning]
    KEY --> AGENT[Opt-in agent / OTel log integration]
    AGENT --> INGEST[HTTPS validated event ingest]
    INGEST --> Q[Queue / worker]
    Q --> DB[(PostgreSQL event + tenant DB)]
    DB --> FEAT[Time-window features]
    FEAT --> RULE[Explainable rules + experimental anomaly scores]
    RULE --> UI[Owner alerts and monitoring / Step 12]
```

**Solid Step 10 functionality**: local account, login, session, domain claim, DNS TXT lookup, verification, user isolation and deletion. Everything from scoped agent key through live alerts is **planned and not implemented**.

## Live event schema (proposed; not an API implemented yet)

A future event should include a stable `event_id`, an authenticated `tenant_id` and `service_id` **derived from a verified ingest credential, never client-supplied as authority**, a `timestamp`, server-validated HTTP method/status, duration, request/response byte counts, and an IP bucket/hash only if justified by the monitoring purpose. Do not collect cookies, authorization headers, passwords, raw query strings, request bodies, or unrestricted User-Agent values by default.

The real-time window grouping must derive from `service_id` and wall-clock time and optional pseudonymous source; lab `simulation_run_id` must remain strictly experimental metadata. Processing should deduplicate events and handle clock skew, rate limits and backpressure. Initial detection should use bounded transparent rule checks; anomaly scores remain supplemental until validated on independent owner-consented data.

## Production-readiness gates

| Gate | Required before real users | Step |
|---|---|---|
| Identity | OIDC / managed auth, verified accounts, MFA, reset, secure web sessions | 11 preflight |
| Persistence | PostgreSQL + migrations + backups + tenant enforcement | 11 preflight |
| DNS proof | Secure DNS TXT verification plus expiry/reverify/transfer lifecycle | 10 prototype / 11 production |
| Ingestion | Scoped rotating/revocable keys, TLS, client quotas, event schema, minimal PII | 11 |
| Live analytics | Worker, time-window features, repeatable policy and evaluation | 12 |
| Security operations | Abuse monitoring, rate limits, observability, alert delivery, retention | 12 |
| Model governance | Independent benign/attack datasets, false-positive confidence and no hidden test tuning | Research track |

## Reference material

- OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- ACME DNS control concept (distinct from CyberSentinel-specific proof): https://letsencrypt.org/docs/challenge-types/

**Note:** DNS TXT verification demonstrates that the applicant can influence DNS records for the nominated hostname at verification time. It does not by itself prove lawful ownership, continued control or authorization to access historical telemetry.
