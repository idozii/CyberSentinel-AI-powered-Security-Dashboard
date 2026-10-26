CyberSentinel - Portfolio 100% Finalization
========================================

Purpose: finalize the zero-cost AI/Data Science internship portfolio.
The 100% target is a reviewable presentation/release checklist, NOT 100% AI accuracy.

From repo root, on updated main and a fresh branch:

1. unzip -o CyberSentinel_Portfolio_100_Finalizer.zip -d .
2. python -m scripts.install_portfolio_finalizer --check-only
3. python -m scripts.install_portfolio_finalizer
4. python -m unittest discover -s tests -p test_portfolio_finalizer.py -v
5. python -m scripts.portfolio_finalizer
6. python -m scripts.portfolio_finalizer --output-dir /tmp/cybersentinel-final-HANDOFF
7. python -m unittest discover -s tests -v
8. python -m scripts.release_audit
9. python -m scripts.normalize_dashes --check
10. git diff --check
11. Commit PR; merge only if full GitHub Actions CI PASS.
12. Finish docs/PORTFOLIO_100_ACCEPTANCE.md human items and publish release.

No real credentials, Neon/Auth0 connection, production deployment or DB migration.
