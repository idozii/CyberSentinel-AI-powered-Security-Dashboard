"""Step 21 deterministic OFFLINE threshold sensitivity experiment.

Uses only hand-labeled synthetic Step 20 fixtures, no live telemetry,
credentials, Neon, Auth0, network, or detector configuration writes.
The baseline is cross-checked against the real in-memory rule engine.
The candidate is selected ONLY from a frozen development partition;
held-out synthetic rows are evaluated after selection, not used to tune.
"""
from __future__ import annotations

import hashlib
import itertools
import json
from collections import Counter

from hosted_api.demo_evaluation import SCENARIOS, _events, _metrics, evaluate
from owner_api.detection import RULES, WINDOW_SECONDS

# Explicit frozen partition. These are not independent real-world examples.
DEVELOPMENT_NAMES = frozenset({
    'low_rate_login_attempts', 'benign_missing_links', 'server_error_burst',
    'below_5xx_threshold', 'traffic_spike', 'below_volume_threshold',
    'split_login_sources', 'split_5xx_sources',
})
VALIDATION_NAMES = frozenset({
    'login_failures', 'missing_url_burst', 'below_login_threshold',
    'below_404_threshold', 'benign_health_polling', 'slow_path_probe',
})
# Pin both synthetic ground truth and rule baseline to fail on unreviewed drift.
PINNED_MANIFEST_SHA256 = '9c0229a691d98b98286fc6f53af0e148dbeaec5c868aee3c89bb2914368ed929'
PINNED_METRICS = {'tp': 4, 'fp': 2, 'fn': 2, 'tn': 48}


def _baseline() -> dict[str, int]:
    return {item[0]: item[1] for item in RULES}


def _predictions(scenario, thresholds: dict[str, int]) -> set[str]:
    """Shadow counter evaluator: identical same-source 60s grouping semantics.

    It cannot mutate DemoStore or the production SQLite/Postgres detectors.
    Its default-threshold output MUST equal real Step 20 DemoStore results.
    """
    # Use a fixed timestamp aligned to a window boundary for stable grouping.
    events = _events(scenario, 1800000000)
    windows: dict[tuple[str, int], Counter] = {}
    for event in events:
        window = event['occurred_at'] // WINDOW_SECONDS
        key = (event['source_ref'], window)
        counts = windows.setdefault(key, Counter())
        counts['requests'] += 1
        counts['failed_logins'] += (event['path_group'] == 'login' and event['status_code'] == 401)
        counts['http_404'] += (event['status_code'] == 404)
        counts['http_5xx'] += (500 <= event['status_code'] <= 599)
    result: set[str] = set()
    for counts in windows.values():
        for rid, _baseline_value, category, _severity, _explanation in RULES:
            if counts[category] >= thresholds[rid]:
                result.add(rid)
    return result


def _partition_scores(rows, thresholds: dict[str, int]) -> dict:
    counts = Counter({'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0})
    details = []
    for case in rows:
        actual = _predictions(case, thresholds)
        expected = set(case.expected_rules)
        details.append({
            'scenario': case.name,
            'detected_rules': sorted(actual),
            'false_positive_rules': sorted(actual - expected),
            'false_negative_rules': sorted(expected - actual),
        })
        for rid, *_ in RULES:
            if rid in actual:
                label = 'tp' if rid in expected else 'fp'
            else:
                label = 'fn' if rid in expected else 'tn'
            counts[label] += 1
    return {'metrics': _metrics(*(counts[k] for k in ('tp','fp','fn','tn'))),
            'scenarios': details, 'scenario_count': len(rows)}


def _score_key(metrics: dict, thresholds: dict, baseline: dict) -> tuple:
    """Development-only objective, favor stable baselines on score ties."""
    return (metrics['f1'] if metrics['f1'] is not None else -1.0,
            metrics['precision'] if metrics['precision'] is not None else -1.0,
            -metrics['fp'],
            -sum(abs(thresholds[k] - baseline[k]) for k in baseline),
            tuple(-thresholds[k] for k in sorted(thresholds)))


def run_shadow_experiment() -> dict:
    baseline_report = evaluate()
    names = {s.name for s in SCENARIOS}
    if (DEVELOPMENT_NAMES & VALIDATION_NAMES or
            DEVELOPMENT_NAMES | VALIDATION_NAMES != names):
        raise RuntimeError('Frozen development and validation partitions do not cover scenarios')
    baseline = _baseline()
    observed_rows = {r['scenario']: set(r['detected_rules']) for r in baseline_report['scenarios']}
    for case in SCENARIOS:
        if _predictions(case, baseline) != observed_rows[case.name]:
            raise RuntimeError('Shadow evaluator diverges from live DemoStore behavior')
    development = [s for s in SCENARIOS if s.name in DEVELOPMENT_NAMES]
    validation = [s for s in SCENARIOS if s.name in VALIDATION_NAMES]
    options = [tuple(range(max(1, baseline[rid] - 1), baseline[rid] + 2)) for rid, *_ in RULES]
    candidates = 0
    best_thresholds = None
    best_score = None
    best_key = None
    for values in itertools.product(*options):
        thresholds = {rid: value for (rid, *_), value in zip(RULES, values)}
        metrics = _partition_scores(development, thresholds)['metrics']
        key = _score_key(metrics, thresholds, baseline)
        candidates += 1
        if best_key is None or key > best_key:
            best_key = key
            best_thresholds = thresholds
            best_score = metrics
    assert best_thresholds is not None and best_score is not None
    baseline_dev = _partition_scores(development, baseline)
    baseline_val = _partition_scores(validation, baseline)
    candidate_dev = _partition_scores(development, best_thresholds)
    candidate_val = _partition_scores(validation, best_thresholds)
    # Exhaustive search uses development only. Validation has no role in selection.
    fingerprint = hashlib.sha256(json.dumps({
        'manifest': baseline_report['manifest_sha256'],
        'development': sorted(DEVELOPMENT_NAMES),
        'validation': sorted(VALIDATION_NAMES),
        'candidate_grid': {r[0]: list(v) for r, v in zip(RULES, options)},
    }, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()
    baseline_f1 = baseline_val['metrics']['f1']
    candidate_f1 = candidate_val['metrics']['f1']
    return {
        'schema_version': 1,
        'suite': 'CyberSentinel Step 21 offline threshold sensitivity',
        'evaluation_unit': 'scenario-rule pair',
        'source_manifest_sha256': baseline_report['manifest_sha256'],
        'experiment_sha256': fingerprint,
        'development_scenarios': [s.name for s in development],
        'validation_scenarios': [s.name for s in validation],
        'candidate_count': candidates,
        'baseline_thresholds': baseline,
        'candidate_thresholds': best_thresholds,
        'baseline_full_metrics': baseline_report['metrics'],
        'baseline_development': baseline_dev,
        'candidate_development': candidate_dev,
        'baseline_validation': baseline_val,
        'candidate_validation': candidate_val,
        'validation_f1_delta': (round(candidate_f1 - baseline_f1, 4)
                                if candidate_f1 is not None and baseline_f1 is not None else None),
        'live_config_changed': False,
        'release_approved': False,
        'limitations': [
            'All labels and splits are synthetic and hand-authored; no independent real-world holdout exists.',
            'Six validation scenarios are far too few for reliable threshold selection.',
            'Thresholds were chosen on development only and must NEVER be auto-applied to live detectors.',
            'One-count threshold sweeps cannot solve all correlated false positives or low-rate misses.',
            'This does not assess the ML detector or production telemetry.',
        ],
    }


def quality_gate() -> dict:
    """Regression guard for the KNOWN baseline, not a proof of detector quality."""
    experiment = run_shadow_experiment()
    metrics = experiment['baseline_full_metrics']
    actual = {k: metrics[k] for k in PINNED_METRICS}
    checks = {
        'pinned_fixture_and_rules': experiment['source_manifest_sha256'] == PINNED_MANIFEST_SHA256,
        'known_baseline_counts': actual == PINNED_METRICS,
        'fixed_partitions': len(experiment['development_scenarios']) == 8 and len(experiment['validation_scenarios']) == 6,
        'candidate_grid_size': experiment['candidate_count'] == 81,
        'no_live_config_mutation': experiment['live_config_changed'] is False and experiment['release_approved'] is False,
    }
    return {'status': 'pass' if all(checks.values()) else 'fail',
            'checks': checks, 'experiment': experiment}


def markdown_report(report: dict) -> str:
    def pct(v):
        return 'N/A' if v is None else f'{v * 100:.2f}%'
    lines = [
        '# CyberSentinel - Step 21 Offline Threshold Sensitivity', '',
        '**Offline synthetic experiment only. No production threshold changes.**', '',
        f"- Fixture and rule fingerprint: `{report['source_manifest_sha256']}`",
        f"- Experiment fingerprint: `{report['experiment_sha256']}`",
        f"- Candidates compared: {report['candidate_count']}",
        f"- Development scenarios: {len(report['development_scenarios'])}",
        f"- Frozen validation scenarios: {len(report['validation_scenarios'])}", '',
        '## Thresholds (baseline vs development-selected)', '',
        '| Rule | Baseline | Candidate |', '|---|---:|---:|',
    ]
    for rid, val in report['baseline_thresholds'].items():
        lines.append(f"| `{rid}` | {val} | {report['candidate_thresholds'][rid]} |")
    lines += ['', '## Performance comparison', '',
              '| Partition | Profile | TP | FP | FN | TN | Precision | Recall | F1 |',
              '|---|---|---:|---:|---:|---:|---:|---:|---:|']
    for part in ('development','validation'):
        for profile in ('baseline', 'candidate'):
            m = report[f'{profile}_{part}']['metrics']
            lines.append(f"| {part} | {profile} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | {pct(m['precision'])} | {pct(m['recall'])} | {pct(m['f1'])} |")
    lines += ['', '## Frozen validation outcomes', '',
              '| Scenario | Candidate false alarms | Candidate misses |', '|---|---|---|']
    for row in report['candidate_validation']['scenarios']:
        lines.append(f"| `{row['scenario']}` | {', '.join(row['false_positive_rules']) or '-'} | {', '.join(row['false_negative_rules']) or '-'} |")
    lines += ['', '## Limitations', '']
    lines.extend('- ' + x for x in report['limitations'])
    return '\n'.join(lines) + '\n'
