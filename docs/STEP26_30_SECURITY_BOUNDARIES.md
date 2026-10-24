# CyberSentinel - Steps 26-30 security boundaries

## Local rehearsal is not an Internet deployment

`deployment/step26/compose.smoke.yml` has `network_mode: none`, no published
ports, read-only filesystem, non-root user and dropped Linux capabilities.
It runs an offline ASGI smoke script, not a public service. The Dockerfile is
not a hardened production supply-chain artifact: its Python base image is not
pinned by digest, package ranges are not locked, and external image scanning,
SBOM, signing and patch management are still required.

The localhost demo remains on 127.0.0.1:8019 and holds only synthetic data.
Auth0 web portal: 127.0.0.1:8007. Postgres ingestion: 127.0.0.1:8008.
Do not expose 8007/8008/8019 or route them through Caddy/ngrok/public tunnels.
No external domain DNS check is bypassed. No remote agent scope expanded.

## Tenant identity

Offline SQL inspection confirms RLS was declared and forced in migration
sources for five tables. Optional runtime inspection is read-only and cannot
prove multi-tenant safety alone. Real two-owner tests on PostgreSQL 17 remain
required in CI; independent security review required for Internet exposure.
Do not connect with `cybersentinel_owner` when testing the runtime role.

## Operations

`/demo/operations` and `.json` report only bounded aggregate counts. The
same loopback and trusted-host checks as the demo apply. No public metrics
service, tracing collector, external logs or tenant labels have been added.
Counters reset with the in-memory process and are not persistent business
monitoring. The JSON endpoint cannot be taken as a uptime/SLO metric.

## Reliability

Offline drills exercise retries, replay, rejected keys/domains, payload size,
stale data, rotation and intended in-memory reset. They do NOT prove durability
under process failure, distributed backpressure, network partitions, reconnect
of a long-running agent or recovery from a real PostgreSQL failure.

## Beta gate

`step30_beta_gate` reports `blocked` if a required checkbox is false and
`manual_independent_review_required` if all are self-attested true. It never
returns authorization to deploy. Domain, TLS, consented traffic, independent
review, incident response, backups/restore and privacy approval are still
external release dependencies. No scripts here provision or modify Neon.
