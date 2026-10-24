# Step 21 - Experimental and security limitations

- Dataset: 14 author-defined synthetic scenarios inherited from Step 20. Their
  labels are not independently adjudicated, and the split is not an independent
  dataset. In particular, there are only 6 synthetic validation scenarios.
- Evaluation unit: scenario-rule pair, not HTTP request, attacker, domain, or
  incident. Micro-aggregated precision/recall are class- and suite-dependent.
- Baseline F1 is 66.67% on all fourteen synthetic cases. The eight development
  cases can be perfectly fit by threshold adjustments, but validation F1 drops
  from 66.67% to 33.33%. This is a deliberate overfitting demonstration.
- Candidate thresholds are in a shadow evaluator that cross-checks default
  settings against the Step 20 DemoStore. Real SQLite and PostgreSQL rule
  thresholds remain unchanged; no automatic promotion exists.
- The regression gate locks the synthetic fixture/rule checksum and baseline
  confusion matrix. PASS means no unreviewed change in THIS suite, not that
  the detector is good, robust, secure, or ready for production.
- Shadow counter evaluator models per-pseudonymous-source, 60-second windows
  on static synthetic events. It does not test event reordering, IP resolution,
  adversarial evasion, partial outages, class imbalance, new traffic patterns,
  RLS, authentication, or ML model metrics.
- To claim improved performance, collect consented, representative labeled
  traffic and use distinct training, validation and temporally separated test
  data. Publish provenance, error taxonomy, confidence intervals and limits.
- No real customer logs, passwords, bearer keys, callback parameters or
  private addresses are copied into synthetic reports. Keep export paths
  outside the repository. No production credentials are needed.
- Do not use these threshold candidates for automated blocking or account
  suspension, and do not imply real-world threat detection efficacy.
