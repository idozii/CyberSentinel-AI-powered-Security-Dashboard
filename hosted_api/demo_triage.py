"""Read-only alert triage helpers for the isolated in-memory local demo.

No access to Auth0, Neon or disk. Alert evidence is aggregated per pseudonymous
source and 60-second rule window, never raw IPs or request URLs.
"""
from __future__ import annotations

from collections import Counter

from owner_api.detection import RULES, WINDOW_SECONDS

ALLOWED_STATUS = frozenset({'all', 'open', 'acknowledged'})
ALLOWED_SEVERITY = frozenset({'all', 'low', 'medium', 'high'})
ALLOWED_RULES = frozenset({'all'} | {item[0] for item in RULES})


def select_alerts(alerts: list[dict], *, status: str = 'all',
                  severity: str = 'all', rule: str = 'all', query: str = '') -> list[dict]:
    if (status not in ALLOWED_STATUS or severity not in ALLOWED_SEVERITY
            or rule not in ALLOWED_RULES or len(query) > 64):
        raise ValueError('Unsupported triage filter')
    term = query.casefold().strip()
    return [dict(a) for a in alerts
            if (status == 'all' or a['status'] == status)
            and (severity == 'all' or a['severity'] == severity)
            and (rule == 'all' or a['rule_id'] == rule)
            and (not term or term in a['title'].casefold() or term in a['rule_id'].casefold())]


def evidence(alert: dict, events: list[dict]) -> dict:
    start = alert['window_start']
    matches = [e for e in events if e['source_ref'] == alert['source_ref']
               and start <= e['occurred_at'] < start + WINDOW_SECONDS]
    by_status = Counter(str(e['status_code']) for e in matches)
    by_group = Counter(e['path_group'] for e in matches)
    return {
        'alert_id': alert['id'], 'rule_id': alert['rule_id'],
        'status': alert['status'], 'severity': alert['severity'],
        'source_hint': alert['source_ref'][:12],
        'window_start': start, 'window_seconds': WINDOW_SECONDS,
        'observed_count': alert['observed_count'],
        'threshold_count': alert['threshold_count'],
        'events_in_window': len(matches),
        'http_status_counts': dict(sorted(by_status.items())),
        'path_group_counts': dict(sorted(by_group.items())),
        'explanation': alert['explanation'],
    }
