# CyberSentinel - Roadmap after Step 20 (planning proposal)

## Current state

Steps 1-20: isolated local lab, NGINX event ingestion, basic ML baseline,
explainable rule alerts, HTTPS posture checker, Auth0 owner login,
PostgreSQL RLS staging, ephemeral local demo and synthetic benchmarks.

Step 20 is NOT a public multi-tenant security SaaS. The private browser
portal and private ingest endpoints bind loopback. The ML baseline is a
prototype. The Step 20 benchmark is synthetic, not production evidence.

## Proposed stages

| Step | Scope | Acceptance checkpoint |
|---|---|---|
| 21 | Offline threshold sensitivity and regression gate | CI detects benchmark drift; no live threshold write |
| 22 | Operator alert triage and evidence UX | Search/filter, acknowledge, timestamps, readable explanations |
| 23 | Agent packaging and lifecycle | Install/start/stop, offline buffering, credential rotation test |
| 24 | More representative labeled tests | Documented label provenance, new benign/adversarial cases, error taxonomy |
| 25 | End-to-end local release | One-command demo, install docs, smoke and recovery test |
| 26 | Secure staging topology and TLS | Owner and agent flows behind reviewed HTTPS boundaries |
| 27 | Production identity and domain onboarding | Tenant authorization, key rotation, DNS ownership threat modeling |
| 28 | Operations and observability | Metrics, structured audit trails, backup/restore and response procedures |
| 29 | Scale, reliability and abuse tests | Ingestion limits, replay, rate limits, fault injection and recovery |
| 30 | Limited-access beta | Real consented traffic from an authorized domain, documented limitations |
| 31+ | Production hardening and external review | Independent security review, privacy/legal review, ops runbook, deployment controls |

Milestones (not guaranteed deadlines): Step 25 - polished local portfolio
MVP (about five steps after Step 20); Step 30 - candidate limited beta (about
10 steps), subject to domain, hosting, security and representative data;
Step 31+ - production readiness depends on actual audits and pilot outcomes.

Critical path for a real hosted service: user controls a DNS domain; obtains
public deployment resources; security testing includes threat modeling and
third-party review; storage, monitoring and incident response are in place;
legal/privacy requirements depend on target regions. Do not disable domain
verification to work around the lack of a domain. Local demonstration remains
independent of production onboarding.
