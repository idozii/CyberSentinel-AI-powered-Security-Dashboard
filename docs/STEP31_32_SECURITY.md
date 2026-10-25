# Step 31-32 Security Boundaries

- The new assets are first-party and served only by the explicit opt-in localhost FastAPI app. They do not call external services or analytics, fetch Internet fonts, or contain embedded secrets.
- Browser CSP now permits only same-origin styles and scripts. Inline JavaScript/CSS is removed. CSRF cookie, strict POST form validation and trusted-origin checks remain unchanged.
- Server-side HTML escaping is required for every domain ID, alert detail, source hint, event property and user-entered filter. The charts show bounded aggregates and use CSS classes, not interpolated CSS or scripts.
- The UI's demo key is shown only in the immediate POST response and never included in normal overview or operations requests. Pseudonymous source refs are truncated to 12 characters in the recent event table.
- All app routes continue to reject non-loopback clients and invalid host headers. Do not reverse proxy or expose port 8019 over the Internet.
- Readiness is read-only and displays the fail-closed example from Step 30. Even an all-true self-attestation does not approve public beta. The route does not read Neon or Auth0 secrets.
- Metrics do not establish actual production uptime, incident detection accuracy, or service reliability. The 12-minute chart is built from synthetic in-memory events and resets when the process restarts.
- The release audit, synthetic quality gate, and PostgreSQL CI integration tests must still pass. A UI redesign is not a security audit.
