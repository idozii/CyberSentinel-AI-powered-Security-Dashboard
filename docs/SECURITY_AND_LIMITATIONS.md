# Security Scope, Threat Model and Responsible Use

## Security posture

**CyberSentinel is not production-ready.** Its intended environment is a user's own, isolated localhost demo (`127.0.0.1`). The demo contains intentionally incorrect authentication attempts and path probes **only against the project-controlled webapp**. Do not point or modify this workload toward other networks without explicit authorization.

## Assets and trust boundaries

| Asset / boundary | Potential issue | Current safeguard | Remaining risk / next step |
|---|---|---|---|
| Local demo proxy | Exposing lab service to public networks | Docker publishes proxy to `127.0.0.1:8080` | Verify local firewall, port forwarding, and Docker settings |
| Attack replay | Unapproved targeting | Script restricts targets to loopback HTTP, bounds request count/concurrency and disables redirects/proxies | These checks are for the provided script, not a general network policy |
| `X-Forwarded-For` and simulated IP | Spoofed attribution | Treated as descriptive, not identity | Do not use as a verified identity or enforcement key |
| Raw logs | IPs, URLs, User-Agent can contain identifying or malicious input | `simulations/runtime/` is Git-ignored | Exclude real user data; set deletion/retention policy if extending project |
| Manifest labels | Label forgery, missing joins | Trusted simulation manifest, NGINX request IDs; duplicate IDs rejected and strict matching available | A malicious/local actor who can edit both files can fabricate labels |
| ML train/test | Data leakage and overfitting | Numeric allowlist, group splits by run ID, threshold from benign validation | Synthetic templates repeat; run separation does not imply independence of attack patterns |
| Serialized model | Malicious pickle deserialization | Dashboard does not load `.joblib`; audit script cautions trusted local models only | Never deserialize external/untrusted `.joblib` files |
| FastAPI artifact endpoints | Path traversal / unbounded reads | Validated run-ID pattern, bounded artifact size/rows, read-only GET endpoints, resolving paths | **No authentication**; exposing beyond localhost could leak experiment details |
| Streamlit dashboard | Accidental public access | Documentation and commands bind to loopback only; API URL limited to localhost | No login, TLS, RBAC, CSRF-oriented security review or deployment controls |
| Source-control releases | Secrets, data, serialized models committed by mistake | `.gitignore`, CI tests and `scripts.release_audit` | Static auditing cannot detect every credential or privacy risk |

## Local-only operation

Use these explicit bindings:

```bash
uvicorn dashboard_api.main:app --host 127.0.0.1 --port 8001
streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8501
docker compose -f simulations/docker-compose.yml up --build -d --wait
```

Never use `--host 0.0.0.0` or public hosting for this implementation without adding authentication, authorization, network controls, rate limiting, privacy reviews and secure operational processes. The demonstration credentials are **not actual secure authentication**.

## Input handling and UI

The API returns selected metrics and bounded CSV-backed records, not arbitrary local file paths. Paths are selected only via a validated experiment identifier; symlinks resolving outside the experiment are rejected. The frontend reads through the local API. This helps with accidental misuse but is not a formal penetration test.

Even with no model inputs from `simulation_run_id`, the source IP is metadata and many numeric signals arise from HTTP response behavior specific to the toy lab. This creates *semantic leakage risk* (the ability to recognize the simulation template) even if direct identifier leakage is removed.

## Security review checklist before any public deployment

1. Remove demo credentials and simulated attack endpoints from public-facing infrastructure.
2. Add authenticated API access, RBAC and per-user data boundaries; review FastAPI `/docs` exposure.
3. Treat `X-Forwarded-For` only from explicitly trusted reverse proxies.
4. Define data minimization, audit logging, retention, privacy rules and incident response.
5. Add rate limits, transport security, supply-chain checks and vulnerability scans.
6. Test with consented diverse real data; validate calibration, false alerts and drift.
7. Assess adversarial and abuse cases before claiming security effectiveness.

**These steps are not implemented in the current repository.** For lab use, keep the system restricted to loopback and avoid ingesting sensitive traffic.
