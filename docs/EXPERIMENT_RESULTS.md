# Experiment Report - CyberSentinel Local Simulation (24 October 2026)

## Executive summary

A controlled localhost simulation produced 160 separately identified replay sessions, 2,678 simulated requests and 160 labeled 60-second windows. A benign-only Isolation Forest demonstrated **poor attack recall (29.17%)** at its preselected benign-validation threshold. A hand-written baseline scored perfectly on this simplified lab, but that outcome does not establish production detection. This report preserves the actual recorded outcomes rather than hiding poor results.

**Evidence type:** user-reported `data_summary.json` and `metrics.json` from a local execution. These runtime files were **not committed to GitHub**; the raw measurement can be reproduced but is not guaranteed identical on another machine.

## Data and experiment design

| Property | Recorded value |
|---|---:|
| Data source | Controlled local Docker/NGINX demo |
| Generation seed | 42 |
| Scenarios | Benign, brute-force, path scanning, mixed |
| Independent runs | 40 per class; 160 total |
| Simulated HTTP requests | 2,678 |
| Successfully matched manifest labels | 2,678 |
| Prior unmatched log events (excluded) | 232 |
| Missing manifest records | 0 |
| Feature windows | 160; 40 per class |
| Window duration | 60 seconds |
| Numeric feature columns | 14 |
| Train / validation / test split | By `simulation_run_id`, ~60/20/20 within each class |
| Benign training windows | 24 |
| Validation windows | 32 (8 benign + 24 attacks) |
| Test windows | 32 (8 benign + 24 attacks) |
| Isolation Forest trees | 200 |
| Threshold | 0.5819654503959275 (benign validation quantile) |
| Requested validation target FPR | 0.05 (not an empirical guarantee) |
| Recorded scikit-learn version | 1.8.0 |

Labels arise from scripted replay scenarios. Malicious intent has not been independently adjudicated. `simulation_run_id` separation reduces *session overlap* across splits, but templates repeat between runs.

## Detector comparison

| Metric | Isolation Forest validation | Isolation Forest test | Fixed-rule test |
|---|---:|---:|---:|
| True negatives | 7 | 8 | 8 |
| False positives | 1 | 0 | 0 |
| False negatives | 17 | 17 | 0 |
| True positives | 7 | 7 | 24 |
| Precision | 0.8750 | **1.0000** | **1.0000** |
| Recall | 0.2917 | **0.2917** | **1.0000** |
| F1 | 0.4375 | **0.4516** | **1.0000** |
| False positive rate | 0.1250 | **0.0000** | **0.0000** |
| Average precision (Isolation Forest scores) | 0.8586 | **0.8839** | Not reported |

### Recall by attack type on test

| Attack scenario | Detected / total | Recall |
|---|---:|---:|
| Brute-force | 5 / 8 | 62.5% |
| Mixed | 2 / 8 | 25.0% |
| Path scanning | **0 / 8** | **0.0%** |
| **All attack types** | **7 / 24** | **29.17%** |

The holdout test attack prevalence was **24/32 = 75%**. Average precision of 0.8839 must be interpreted against that imbalanced prevalence; it is not comparable to AP measured on a realistic low-prevalence SOC stream. The rule baseline benefited from fixed, clear synthetic patterns: repeated 401 errors and paths yielding 404, with few analogous benign errors.

## What the results support

- The end-to-end labeling pipeline matched all simulated requests in this run, with no manifest gaps.
- The 14-feature transformation and run-level split executed without errors; the saved threshold was produced using benign validation data.
- Isolation Forest is **not** a reliable standalone detector for these scenarios at the selected threshold: it missed 17/24 attack windows, including every scanning window.
- The hand-written heuristic is a useful *sanity-check benchmark*, not evidence of superiority on unseen real-world traffic.

## Important limitations

1. **Synthetic data:** benign traffic is clean, while attack traffic includes explicit 401/404 patterns; the evaluation is structurally easy for hand-coded rules.
2. **Small benign validation sample:** eight benign windows cannot resolve a target 5% FPR precisely; one false positive already means 12.5%.
3. **Repeated attack templates:** same paths and response patterns recur across independent runs. A run-disjoint split is not a template-disjoint or cross-dataset evaluation.
4. **Offline grouping:** windows include simulation run IDs as grouping metadata; a real-time detector cannot rely on these IDs.
5. **Model selection risk:** this recorded test result and the later robustness what-if results must not be used to retune a model while claiming the original test remains untouched.
6. **No external benchmark:** no UNSW-NB15, NSL-KDD or production SOC stream was used for these metrics.

## Future experimental work

Collect more diverse *consented/local* normal behavior including occasional login mistakes, nonexistent routes and bursty legitimate traffic; create separate time-based or scenario-template-disjoint holdouts; compare against genuinely new traces; report confidence intervals and class prevalence; and evaluate operational FPR/alert burden. Treat a new experiment with new data as a new version, not a correction of the fixed holdout outcome above.

See [Reproducibility](REPRODUCIBILITY.md) for commands and [Security & limitations](SECURITY_AND_LIMITATIONS.md) for deployment caveats.
