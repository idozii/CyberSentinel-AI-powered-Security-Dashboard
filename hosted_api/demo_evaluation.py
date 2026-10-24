"""Deterministic synthetic rule evaluation against the Step 19 in-memory ingest.

No HTTP requests, real logs, credentials, database or live tenant data.
Ground truth is manually chosen for each scenario, not independently observed.
Evaluation unit: (scenario, rule) pair; not an HTTP event or an attack.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from hosted_api.local_demo import DemoStore
from owner_api.detection import RULES


@dataclass(frozen=True)
class Scenario:
    name: str
    count: int
    path_group: str
    status_code: int
    expected_rules: tuple[str, ...] = ()
    source_split: tuple[int, ...] = ()
    explanation: str = ''


SCENARIOS: tuple[Scenario, ...] = (
    Scenario('login_failures', 5, 'login', 401, ('repeated_login_failures',),
             explanation='Five 401 responses in one source window'),
    Scenario('missing_url_burst', 8, 'other', 404, ('http_404_burst',),
             explanation='Eight 404 responses in one source window'),
    Scenario('server_error_burst', 5, 'api', 503, ('server_error_burst',),
             explanation='Five 503 responses in one source window'),
    Scenario('traffic_spike', 40, 'api', 200, ('request_volume_spike',),
             explanation='Forty requests in one source window'),
    Scenario('below_login_threshold', 4, 'login', 401,
             explanation='Four 401 responses below the alert threshold'),
    Scenario('below_404_threshold', 7, 'other', 404,
             explanation='Seven 404 responses below the alert threshold'),
    Scenario('below_5xx_threshold', 4, 'api', 503,
             explanation='Four 503 responses below the alert threshold'),
    Scenario('below_volume_threshold', 39, 'api', 200,
             explanation='Thirty-nine 200 responses below the alert threshold'),
    Scenario('benign_missing_links', 8, 'other', 404,
             explanation='Benign broken links can look like a scan - known false positive'),
    Scenario('benign_health_polling', 40, 'health', 200,
             explanation='Legitimate monitoring polling can trip volume rule - known false positive'),
    Scenario('low_rate_login_attempts', 4, 'login', 401, ('repeated_login_failures',),
             explanation='Manually labeled suspicious despite fewer than five failures - known miss'),
    Scenario('slow_path_probe', 7, 'other', 404, ('http_404_burst',),
             explanation='Manually labeled suspicious despite fewer than eight 404s - known miss'),
    Scenario('split_login_sources', 5, 'login', 401, source_split=(3, 2),
             explanation='No alert when login failures are divided across two sources'),
    Scenario('split_5xx_sources', 5, 'api', 503, source_split=(3, 2),
             explanation='No alert when 5xx responses are divided across two sources'),
)


def _safe_ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _metrics(tp: int, fp: int, fn: int, tn: int) -> dict:
    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    f1 = _safe_ratio(2 * tp, 2 * tp + fp + fn)
    return {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
            'precision': precision, 'recall': recall, 'f1': f1}


def _events(scenario: Scenario, timestamp: int) -> list[dict]:
    split = scenario.source_split or (scenario.count,)
    if any(n <= 0 for n in split) or sum(split) != scenario.count:
        raise ValueError('Scenario source split does not match event count')
    source_indices = [source for source, count in enumerate(split) for _ in range(count)]
    output = []
    for index, source_index in enumerate(source_indices):
        seed = f'{scenario.name}:{index}'.encode('ascii')
        source_seed = f'{scenario.name}:source:{source_index}'.encode('ascii')
        output.append({
            'event_id': hashlib.sha256(seed).hexdigest()[:32],
            'occurred_at': timestamp,
            'source_ref': hashlib.sha256(source_seed).hexdigest()[:32],
            'method': 'GET', 'path_group': scenario.path_group,
            'status_code': scenario.status_code, 'duration_ms': 3.0,
            'request_bytes': 128, 'response_bytes': 64,
        })
    return output


def evaluate(*, scenarios: tuple[Scenario, ...] = SCENARIOS,
             clock: float | None = None) -> dict:
    """Execute real DemoStore ingest in an isolated fresh store per scenario.

    Returning aggregate counts only - no issued bearer tokens, domain UUIDs,
    source references or event IDs escape this evaluation function.
    """
    instant = time.time() if clock is None else float(clock)
    if not 0 < instant < 4102444800:
        raise ValueError('Clock outside supported range')
    timestamp = int(instant)
    ids = tuple(rule[0] for rule in RULES)
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate detector rule IDs')
    rows = []
    overall = {'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0}
    by_rule = {rule_id: {'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0} for rule_id in ids}
    seen_scenarios: set[str] = set()
    for case in scenarios:
        if case.name in seen_scenarios:
            raise ValueError('Duplicate scenario name')
        seen_scenarios.add(case.name)
        if not set(case.expected_rules).issubset(ids):
            raise ValueError('Scenario has unknown expected rule')
        db = DemoStore()  # fresh, in-memory; NEVER touches staging
        key = db.issue_key()
        events = _events(case, timestamp)
        batches = [events[i:i + 25] for i in range(0, len(events), 25)]
        accepted = duplicates = 0
        for batch in batches:
            result = db.ingest(key, db.domain_id, batch)
            accepted += result['accepted']
            duplicates += result['duplicates']
        actual = set(alert['rule_id'] for alert in db.snapshot()['alerts'])
        if accepted != len(events) or duplicates:
            raise RuntimeError('Unexpected initial ingestion result')
        # Ingestion replay tests the actual idempotency path, not just set logic.
        replayed = 0
        for batch in batches:
            replay = db.ingest(key, db.domain_id, batch)
            if replay['accepted'] or replay['alerts_updated']:
                raise RuntimeError('Replay must not create new records or alerts')
            replayed += replay['duplicates']
        if replayed != len(events):
            raise RuntimeError('Replay did not deduplicate every event')
        row = {'scenario': case.name, 'events': len(events),
               'expected_rules': sorted(case.expected_rules),
               'detected_rules': sorted(actual),
               'false_positive_rules': sorted(actual - set(case.expected_rules)),
               'false_negative_rules': sorted(set(case.expected_rules) - actual),
               'replay_duplicates': replayed, 'explanation': case.explanation}
        rows.append(row)
        for rule_id in ids:
            expected = rule_id in case.expected_rules
            detected = rule_id in actual
            label = 'tp' if expected and detected else ('fp' if detected else ('fn' if expected else 'tn'))
            overall[label] += 1
            by_rule[rule_id][label] += 1
    manifest = {'scenarios': [asdict(s) for s in scenarios], 'rules': [list(r) for r in RULES]}
    digest = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()
    return {
        'schema_version': 1, 'suite': 'CyberSentinel Step 20 synthetic rule benchmark',
        'evaluation_unit': 'scenario-rule pair',
        'evaluated_at_utc': datetime.fromtimestamp(instant, timezone.utc).isoformat(),
        'scenario_count': len(rows), 'rule_count': len(ids),
        'scenario_rule_pairs': len(rows) * len(ids),
        'total_synthetic_events': sum(r['events'] for r in rows),
        'replayed_duplicates': sum(r['replay_duplicates'] for r in rows),
        'manifest_sha256': digest, 'metrics': _metrics(**overall),
        'per_rule': {k: _metrics(**v) for k, v in by_rule.items()},
        'scenarios': rows,
        'limitations': [
            'Synthetic, manually assigned scenario labels; not a real-world attack dataset.',
            'Measured unit is scenario-rule pair, not events, users, attacks or time windows in production.',
            'Examples intentionally include benign false alarms and low-rate missed behavior.',
            'Runs only the Step 19 DemoStore rule engine; does not test ML, Neon RLS or production security.',
            'No confidence intervals or generalization claims are supported by this small fixture set.',
        ],
    }


def markdown_report(report: dict) -> str:
    m = report['metrics']
    fmt = lambda n: 'N/A' if n is None else f'{n:.4f}'
    lines = [
        '# CyberSentinel - Step 20 Synthetic Detection Evaluation', '',
        f"- Run UTC: {report['evaluated_at_utc']}",
        f"- Fixture/rule manifest SHA-256: `{report['manifest_sha256']}`",
        f"- Evaluation unit: {report['evaluation_unit']}",
        f"- Scenarios: {report['scenario_count']}; rule pairs: {report['scenario_rule_pairs']}",
        f"- Synthetic events processed: {report['total_synthetic_events']}",
        f"- Replay duplicates rejected: {report['replayed_duplicates']}", '',
        '## Micro-aggregated confusion matrix', '',
        '| TP | FP | FN | TN | Precision | Recall | F1 |',
        '|---:|---:|---:|---:|---:|---:|---:|',
        f"| {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['f1'])} |",
        '', '## Per-rule performance', '',
        '| Rule | TP | FP | FN | TN | Precision | Recall | F1 |',
        '|---|---:|---:|---:|---:|---:|---:|---:|',
    ]
    for rid, v in report['per_rule'].items():
        lines.append(f"| `{rid}` | {v['tp']} | {v['fp']} | {v['fn']} | {v['tn']} | {fmt(v['precision'])} | {fmt(v['recall'])} | {fmt(v['f1'])} |")
    lines.extend(['', '## Labeled scenarios', '',
                  '| Scenario | Expected rules | Detected rules | False positives | False negatives |',
                  '|---|---|---|---|---|'])
    for row in report['scenarios']:
        col = lambda k: ', '.join(row[k]) or '-'
        lines.append(f"| `{row['scenario']}` | {col('expected_rules')} | {col('detected_rules')} | {col('false_positive_rules')} | {col('false_negative_rules')} |")
    lines.extend(['', '## Limitations', ''])
    lines.extend(f'- {item}' for item in report['limitations'])
    lines.append('')
    return '\n'.join(lines)
