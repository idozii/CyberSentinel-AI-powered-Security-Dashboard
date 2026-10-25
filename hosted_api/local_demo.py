"""Explicit opt-in, process-memory-only CyberSentinel demo for localhost.

This is not the Auth0 owner portal, the PostgreSQL store, or a real DNS verifier.
No production credential, identity, event, or migration is imported or touched.
Run ONLY at http://127.0.0.1:8019 with one worker.
"""
from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import os
import secrets
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Request, Security
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from hosted_api.monitoring_models import TelemetryEvent
from owner_api.detection import RULES, WINDOW_SECONDS
from hosted_api.soc_ui import page as render_soc_page, dashboard as render_soc_dashboard

DEMO_FLAG = 'CYBERSENTINEL_LOCAL_DEMO'
DEMO_ORIGIN = 'http://127.0.0.1:8019'
TOKEN_PREFIX = 'csd_'
MAX_EVENTS = 500
MAX_PER_BATCH = 25
MAX_PER_MINUTE = 120
RULE_TITLES = {
    'repeated_login_failures': 'Repeated login failures',
    'http_404_burst': 'HTTP 404 response burst',
    'server_error_burst': 'HTTP 5xx error burst',
    'request_volume_spike': 'High request volume',
}
METHODS = frozenset({'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'})
GROUPS = frozenset({'login', 'health', 'admin', 'api', 'other'})
AUTH = HTTPBearer(auto_error=False)
SOC_ASSETS = Path(__file__).resolve().parent / 'assets'


class DemoBatch(BaseModel):
    model_config = ConfigDict(extra='forbid')
    domain_id: uuid.UUID
    events: list[TelemetryEvent] = Field(min_length=1, max_length=MAX_PER_BATCH)


class DemoStore:
    """Single intentionally fake tenant, bounded process-memory state and atomic writes."""

    def __init__(self):
        self.lock = threading.RLock()
        self.domain_id = uuid.uuid4()
        self._token_hash: str | None = None
        self.events: list[dict] = []
        self.ids: set[str] = set()
        self.alerts: dict[tuple[str, int, str], dict] = {}
        self.issued_at: float | None = None
        self.started_at = time.monotonic()
        self.operation_counts = {
            'keys_issued': 0, 'batches_received': 0, 'events_accepted': 0,
            'duplicates_ignored': 0, 'alerts_updated': 0,
            'invalid_credentials': 0, 'invalid_events': 0,
            'capacity_rejections': 0,
        }

    def issue_key(self) -> str:
        with self.lock:
            token = TOKEN_PREFIX + secrets.token_urlsafe(32)
            self._token_hash = hashlib.sha256(token.encode('ascii')).hexdigest()
            self.issued_at = time.time()
            self.operation_counts['keys_issued'] += 1
            # Replacing a token must never silently preserve old demonstration data.
            self.events.clear()
            self.ids.clear()
            self.alerts.clear()
            return token

    def _validate(self, token: str, domain_id: uuid.UUID, events: list[dict]):
        valid = (isinstance(token, str) and token.startswith(TOKEN_PREFIX)
                 and self._token_hash is not None
                 and secrets.compare_digest(hashlib.sha256(token.encode()).hexdigest(), self._token_hash))
        if not valid or domain_id != self.domain_id:
            self.operation_counts['invalid_credentials'] += 1
            raise HTTPException(401, detail='Invalid local demo agent key or domain')
        now = time.time()
        for event in events:
            if (type(event['occurred_at']) is not int or abs(event['occurred_at'] - now) > 300
                    or event['method'] not in METHODS or event['path_group'] not in GROUPS):
                self.operation_counts['invalid_events'] += 1
                raise HTTPException(422, detail='Invalid or stale demo event')
        return now

    def ingest(self, token: str, domain_id: uuid.UUID, events: list[dict]) -> dict:
        with self.lock:
            self.operation_counts['batches_received'] += 1
            now = self._validate(token, domain_id, events)
            new = [ev for ev in events if ev['event_id'] not in self.ids]
            # Reject duplicate event IDs even inside a single batch. No partial writes.
            unique_new = {ev['event_id']: ev for ev in new}
            newly = list(unique_new.values())
            if len(self.events) + len(newly) > MAX_EVENTS:
                self.operation_counts['capacity_rejections'] += 1
                raise HTTPException(429, detail='Local demo capacity reached; issue a new key to reset')
            minute_count = sum(1 for ev in self.events if ev['received_at'] >= now - 60)
            if minute_count + len(newly) > MAX_PER_MINUTE:
                self.operation_counts['capacity_rejections'] += 1
                raise HTTPException(429, detail='Local demo rate limit reached')
            for ev in newly:
                record = {**ev, 'received_at': now}
                self.events.append(record)
                self.ids.add(record['event_id'])
            updated = 0
            windows = {(ev['source_ref'], (ev['occurred_at'] // WINDOW_SECONDS) * WINDOW_SECONDS) for ev in newly}
            for source, start in sorted(windows):
                window = [ev for ev in self.events if ev['source_ref'] == source
                          and start <= ev['occurred_at'] < start + WINDOW_SECONDS]
                counts = {
                    'requests': len(window),
                    'failed_logins': sum(ev['path_group'] == 'login' and ev['status_code'] == 401 for ev in window),
                    'http_404': sum(ev['status_code'] == 404 for ev in window),
                    'http_5xx': sum(500 <= ev['status_code'] <= 599 for ev in window),
                }
                for rule_id, threshold, counter, severity, explanation in RULES:
                    count = counts[counter]
                    if count < threshold:
                        continue
                    index = (source, start, rule_id)
                    previous = self.alerts.get(index)
                    if previous is None:
                        self.alerts[index] = {
                            'id': uuid.uuid4().hex, 'rule_id': rule_id,
                            'title': RULE_TITLES[rule_id], 'severity': severity,
                            'explanation': explanation, 'status': 'open',
                            'observed_count': count, 'threshold_count': threshold,
                            'window_start': start, 'source_ref': source,
                        }
                        updated += 1
                    elif count > previous['observed_count']:
                        previous['observed_count'] = count
                        updated += 1
            self.operation_counts['events_accepted'] += len(newly)
            self.operation_counts['duplicates_ignored'] += len(events) - len(newly)
            self.operation_counts['alerts_updated'] += updated
            return {'accepted': len(newly), 'duplicates': len(events) - len(newly),
                    'alerts_updated': updated, 'domain_id': self.domain_id.hex, 'mode': 'local-demo'}

    def acknowledge(self, alert_id: str) -> bool:
        with self.lock:
            for alert in self.alerts.values():
                if alert['id'] == alert_id:
                    alert['status'] = 'acknowledged'
                    alert['acknowledged_at'] = time.time()
                    return True
            return False

    def triage(self, *, status: str = 'all', severity: str = 'all',
               rule: str = 'all', query: str = '') -> list[dict]:
        from hosted_api.demo_triage import select_alerts
        with self.lock:
            return select_alerts(list(self.alerts.values()), status=status,
                                 severity=severity, rule=rule, query=query)

    def alert_evidence(self, alert_id: str) -> dict | None:
        from hosted_api.demo_triage import evidence
        with self.lock:
            for alert in self.alerts.values():
                if alert['id'] == alert_id:
                    return evidence(alert, self.events)
        return None

    def operations_snapshot(self) -> dict:
        """Aggregate counters only - never include agent key, domain or source IDs."""
        with self.lock:
            return {
                'mode': 'local-demo-only', 'persistent': False,
                'uptime_seconds': max(0, int(time.monotonic() - self.started_at)),
                'event_capacity': MAX_EVENTS,
                'events_in_memory': len(self.events),
                'alerts_in_memory': len(self.alerts),
                'counts': dict(self.operation_counts),
                'warning': 'Synthetic local counters, reset on process restart; not hosted observability.',
            }

    def snapshot(self) -> dict:
        with self.lock:
            # UI aggregates stay anonymous; never export keys, raw IPs or URLs.
            minute = (int(time.time()) // 60) * 60
            activity = [{'time': datetime.fromtimestamp(minute - offset * 60, timezone.utc).strftime('%H:%M'),
                         'count': 0, 'start': minute - offset * 60}
                        for offset in range(11, -1, -1)]
            by_start = {row['start']: row for row in activity}
            statuses = {'2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0}
            for event in self.events:
                occurred = (int(event['occurred_at']) // 60) * 60
                if occurred in by_start:
                    by_start[occurred]['count'] += 1
                group = str(int(event['status_code']) // 100) + 'xx'
                if group in statuses:
                    statuses[group] += 1
            for row in activity:
                del row['start']
            return {'domain_id': self.domain_id.hex,
                    'key_issued': self._token_hash is not None,
                    'events': [dict(row) for row in reversed(self.events[-20:])],
                    'total_events': len(self.events),
                    'alerts': [dict(row) for row in sorted(
                        self.alerts.values(), key=lambda row: row['window_start'], reverse=True)],
                    'total_alerts': len(self.alerts),
                    'overview': {'activity': activity, 'http_status': statuses}}


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _page(title: str, content: str) -> HTMLResponse:
    return HTMLResponse(render_soc_page(title, content))


def create_demo_app(store: DemoStore | None = None, *, enabled: bool | None = None) -> FastAPI:
    allowed = os.getenv(DEMO_FLAG) == '1' if enabled is None else enabled
    if not allowed:
        raise RuntimeError('Local Demo disabled. Explicitly export CYBERSENTINEL_LOCAL_DEMO=1 to opt in.')
    db = store if store is not None else DemoStore()
    app = FastAPI(title='CyberSentinel Local Demo', docs_url=None,
                  redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1', 'localhost', 'testserver'])
    app.state.demo = db

    @app.get('/demo/assets/soc.css')
    def soc_stylesheet():
        return Response((SOC_ASSETS / 'soc.css').read_text(encoding='utf-8'), media_type='text/css')

    @app.get('/demo/assets/soc.js')
    def soc_script():
        return Response((SOC_ASSETS / 'soc.js').read_text(encoding='utf-8'), media_type='text/javascript')

    @app.middleware('http')
    async def loopback(req: Request, call_next):
        peer = req.client.host if req.client else ''
        try:
            local = ipaddress.ip_address(peer).is_loopback
        except ValueError:
            local = peer == 'testclient'
        if not local:
            return JSONResponse({'detail': 'Local Demo requires loopback'}, status_code=403)
        if req.url.path == '/agent/v1/ingest':
            length = req.headers.get('content-length', '')
            if not length.isdecimal():
                return JSONResponse({'detail': 'Content-Length required'}, status_code=411)
            if int(length) > 32768:
                return JSONResponse({'detail': 'Demo batch too large'}, status_code=413)
        # Never use this app behind a reverse proxy to bypass loopback restrictions.
        response = await call_next(req)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # HTML form navigation with no-referrer can send Origin: null.
        # same-origin retains strict Origin+CSRF checks without this conflict.
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'"
        return response

    def csrf(req: Request) -> str:
        token = req.cookies.get('demo_csrf', '')
        if len(token) != 43:
            raise HTTPException(403, detail='Open the demo dashboard first')
        return token

    async def authorize_form(req: Request) -> dict[str, str]:
        token = csrf(req)
        if req.headers.get('origin') not in (None, DEMO_ORIGIN):
            raise HTTPException(403, detail='Invalid form origin')
        if req.headers.get('content-type', '').split(';')[0].lower() != 'application/x-www-form-urlencoded':
            raise HTTPException(415, detail='Form required')
        raw = await req.body()
        if len(raw) > 1024:
            raise HTTPException(413, detail='Form too large')
        try:
            params = parse_qs(raw.decode('utf-8'), strict_parsing=True, keep_blank_values=True, max_num_fields=3)
        except (ValueError, UnicodeError) as exc:
            raise HTTPException(422, detail='Invalid form') from exc
        if any(len(val) != 1 for val in params.values()):
            raise HTTPException(422, detail='Ambiguous form')
        result = {key: val[0] for key, val in params.items()}
        if not secrets.compare_digest(result.get('_csrf', ''), token):
            raise HTTPException(403, detail='CSRF check failed')
        return result

    def dashboard(req: Request, message: str = '') -> HTMLResponse:
        token = req.cookies.get('demo_csrf', '')
        if len(token) != 43:
            token = secrets.token_urlsafe(32)
        contents = render_soc_dashboard(db.snapshot(), token, message)
        response = _page('Security overview', contents)
        response.set_cookie('demo_csrf', token, path='/', max_age=3600,
                            httponly=True, samesite='strict', secure=False)
        return response

    @app.get('/')
    def index(req: Request):
        return dashboard(req)

    @app.get('/demo/evaluation')
    def evaluation():
        # Deliberately isolated from app.state.demo and from any live or staging store.
        # No external traffic, credentials, host data or database access.
        from hosted_api.demo_evaluation import evaluate
        result = evaluate()
        score = result['metrics']
        fmt = lambda x: 'N/A' if x is None else str(round(x * 100, 2)) + '%'
        content = ('<p class="notice">Synthetic labeled fixtures only. This is not '
                   'production detection accuracy or a real-world attack benchmark.</p>')
        content += ('<div class="grid"><div class="card">Scenario-rule pairs<div class="value">'
                    + _esc(result['scenario_rule_pairs']) + '</div></div>')
        for key, label in (('precision', 'Precision'), ('recall', 'Recall'), ('f1', 'F1-score')):
            content += ('<div class="card">' + label + '<div class="value">'
                        + _esc(fmt(score[key])) + '</div></div>')
        content += '</div>'
        content += ('<p>TP: ' + _esc(score['tp']) + ' / FP: ' + _esc(score['fp'])
                    + ' / FN: ' + _esc(score['fn']) + ' / TN: ' + _esc(score['tn']) + '</p>')
        content += '<h2>Known false alarms and missed scenarios</h2>'
        content += '<table><tr><th>Scenario</th><th>False alarms</th><th>Misses</th></tr>'
        for row in result['scenarios']:
            if not row['false_positive_rules'] and not row['false_negative_rules']:
                continue
            content += ('<tr><td>' + _esc(row['scenario']) + '</td><td>'
                        + _esc(', '.join(row['false_positive_rules']) or '-') + '</td><td>'
                        + _esc(', '.join(row['false_negative_rules']) or '-') + '</td></tr>')
        content += '</table>'
        content += ('<p>Full JSON and Markdown exports are generated locally with '
                    '<code>python -m scripts.step20_evaluate --output-dir /tmp/cs-step20-report</code>. '
                    'No evaluation data is stored on this server.</p>')
        content += ('<p><a href="/">Back to local dashboard</a></p>')
        return _page('Synthetic detection evaluation - Step 20', content)

    @app.get('/demo/tuning')
    def tuning():
        # Read-only synthetic simulation; never reads active demo credentials,
        # Auth0, staging Postgres, or real telemetry.
        from hosted_api.demo_tuning import run_shadow_experiment
        result = run_shadow_experiment()
        content = ('<p class="notice">Offline synthetic sensitivity only. Candidate thresholds '
                   'must not be applied to staging, production, or the active demo detector.</p>')
        content += ('<p>Development scenarios: ' + _esc(len(result['development_scenarios']))
                    + ' | Frozen synthetic validation scenarios: ' + _esc(len(result['validation_scenarios']))
                    + ' | Candidates: ' + _esc(result['candidate_count']) + '</p>')
        content += '<h2>Thresholds</h2><table><tr><th>Rule</th><th>Baseline</th><th>Offline candidate</th></tr>'
        for rid, value in result['baseline_thresholds'].items():
            content += ('<tr><td>' + _esc(rid) + '</td><td>' + _esc(value) + '</td><td>'
                        + _esc(result['candidate_thresholds'][rid]) + '</td></tr>')
        content += '</table><h2>F1 comparison</h2><table><tr><th>Partition</th><th>Baseline</th><th>Candidate</th></tr>'
        for part in ('development', 'validation'):
            base = result['baseline_' + part]['metrics']['f1']
            candidate = result['candidate_' + part]['metrics']['f1']
            def fmt(value):
                return 'N/A' if value is None else str(round(value * 100, 2)) + '%'
            content += ('<tr><td>' + _esc(part) + '</td><td>' + _esc(fmt(base))
                        + '</td><td>' + _esc(fmt(candidate)) + '</td></tr>')
        content += '</table>'
        content += ('<p>Candidate selection used development rows only. The holdout contains '
                    'only six manually labeled synthetic scenarios and is not independent real-world evidence.</p>')
        content += ('<p>Export with <code>python -m scripts.step21_quality_gate '
                    '--output-dir /tmp/cyber-step21-report</code>.</p>')
        content += '<p><a href="/">Back to local dashboard</a></p>'
        return _page('Synthetic threshold sensitivity - Step 21', content)

    @app.get('/demo/alerts')
    def triage_page(status: str = 'all', severity: str = 'all',
                    rule: str = 'all', query: str = ''):
        from hosted_api.demo_triage import ALLOWED_RULES
        try:
            rows = db.triage(status=status, severity=severity, rule=rule, query=query)
        except ValueError as exc:
            raise HTTPException(422, detail=str(exc)) from exc
        lines = ['<p class="notice">Synthetic local alerts only. Evidence uses aggregate categories; '
                 'no raw IP addresses or URLs are retained.</p>',
                 '<form method="get" action="/demo/alerts">']
        for name, options, active in (
            ('status', ('all', 'open', 'acknowledged'), status),
            ('severity', ('all', 'low', 'medium', 'high'), severity),
            ('rule', tuple(sorted(ALLOWED_RULES)), rule),
        ):
            lines.append('<label>'+_esc(name)+' <select name="'+_esc(name)+'">')
            for option in options:
                selected = ' selected' if option == active else ''
                lines.append('<option value="'+_esc(option)+'"'+selected+'>'+_esc(option)+'</option>')
            lines.append('</select></label> ')
        lines.append('<label>Rule search <input name="query" maxlength="64" value="'+_esc(query)+'"></label> ')
        lines.append('<button type="submit">Filter</button></form>')
        lines.append('<p>Matching alerts: '+_esc(len(rows))+'</p>')
        for alert in rows:
            lines.append('<div class="card"><strong>'+_esc(alert['title'])+'</strong> - '
                         +_esc(alert['severity'])+' - '+_esc(alert['status'])+' '
                         +'<a href="/demo/alerts/'+_esc(alert['id'])+'">View evidence</a></div>')
        lines.append('<p><a href="/">Back to local dashboard</a></p>')
        return _page('Local alert triage - Step 22', ''.join(lines))

    @app.get('/demo/alerts/{alert_id}')
    def alert_detail(alert_id: str):
        if len(alert_id) != 32 or any(ch not in '0123456789abcdef' for ch in alert_id):
            raise HTTPException(404, detail='Demo alert not found')
        item = db.alert_evidence(alert_id)
        if item is None:
            raise HTTPException(404, detail='Demo alert not found')
        lines = ['<p><strong>'+_esc(item['rule_id'])+'</strong> - '+_esc(item['status'])+'</p>',
                 '<p>'+_esc(item['explanation'])+'</p>',
                 '<p>Observed '+_esc(item['observed_count'])+' / threshold '
                 +_esc(item['threshold_count'])+'</p>',
                 '<p>Time window: '+_esc(item['window_start'])+' (60 seconds UTC epoch)</p>',
                 '<p>Pseudonymous source prefix: '+_esc(item['source_hint'])+'</p>',
                 '<p>Events in evidence window: '+_esc(item['events_in_window'])+'</p>',
                 '<h3>HTTP status groups</h3><ul>']
        for code, n in item['http_status_counts'].items():
            lines.append('<li>'+_esc(code)+': '+_esc(n)+'</li>')
        lines.append('</ul><h3>Path categories</h3><ul>')
        for group, n in item['path_group_counts'].items():
            lines.append('<li>'+_esc(group)+': '+_esc(n)+'</li>')
        lines.append('</ul><p><a href="/demo/alerts">Back to triage</a></p>')
        return _page('Alert evidence - Step 22', ''.join(lines))

    @app.get('/demo/readiness')
    def readiness_page():
        # Read the bundled fail-closed example only. Not user evidence or an approval.
        from scripts.step30_beta_gate import DEFAULT, assess
        result = assess(json.loads(DEFAULT.read_text(encoding='utf-8')))
        lines = [
            '<p class="notice">Beta gate: BLOCKED. This is an offline, self-assessment '
            'of missing prerequisites, not permission to deploy.</p>',
            '<div class="grid"><div class="card"><small>Release decision</small>'
            '<div class="value">NO-GO</div><p>Public deployment prohibited</p></div>',
            '<div class="card"><small>Conditions outstanding</small><div class="value">'
            + _esc(len(result['missing_conditions'])) + ' / '
            + _esc(result['required_conditions']) + '</div></div></div>',
            '<h2>Outstanding beta prerequisites</h2><table>'
            '<tr><th>Requirement</th><th>State</th></tr>'
        ]
        for item in result['missing_conditions']:
            lines.append('<tr><td>' + _esc(item.replace('_', ' ').capitalize())
                         + '</td><td>Not evidenced</td></tr>')
        lines.append('</table><p>Review <code>docs/BETA_GO_NO_GO.md</code> and obtain '
                     'independent security validation before any public release.</p>')
        return _page('Beta readiness - Step 31', ''.join(lines))

    @app.get('/demo/operations.json')
    def operations_json():
        return db.operations_snapshot()

    @app.get('/demo/operations')
    def operations_page():
        import html as _html
        snapshot = db.operations_snapshot()
        lines = [
            '<p class="notice">Local synthetic aggregate counters only. '
            'No production SLO, uptime guarantee or cloud health inference.</p>',
            '<p>Process uptime (seconds): <strong>' + str(snapshot['uptime_seconds']) + '</strong></p>',
            '<p>Events in memory: <strong>' + str(snapshot['events_in_memory']) + '</strong></p>',
            '<p>Alerts in memory: <strong>' + str(snapshot['alerts_in_memory']) + '</strong></p>',
            '<table><tr><th>Counter</th><th>Count</th></tr>',
        ]
        for name, value in sorted(snapshot['counts'].items()):
            lines.append('<tr><td>' + _html.escape(name) + '</td><td>' + str(value) + '</td></tr>')
        lines.append('</table><p><a href="/">Back to local dashboard</a></p>')
        return _page('Local operations - Step 28', ''.join(lines))

    @app.post('/demo/key')
    async def key(req: Request):
        await authorize_form(req)
        token = db.issue_key()
        return dashboard(req, '<strong>Copy this agent key now - shown once:</strong><p><code>'+
                         _esc(token)+'</code></p><p>Do not commit this token.</p>')

    @app.post('/demo/ack/{alert_id}')
    async def ack(req: Request, alert_id: str):
        await authorize_form(req)
        if not db.acknowledge(alert_id):
            raise HTTPException(404, detail='Demo alert not found')
        return dashboard(req, '<p>Alert acknowledged.</p>')

    @app.post('/agent/v1/ingest')
    def ingest(batch: DemoBatch, credentials: HTTPAuthorizationCredentials | None = Security(AUTH)):
        if not credentials or credentials.scheme.lower() != 'bearer':
            raise HTTPException(401, detail='Local demo agent credentials required')
        return db.ingest(credentials.credentials, batch.domain_id, [e.model_dump() for e in batch.events])

    @app.get('/health')
    def health():
        return {'status': 'ok', 'mode': 'isolated-local-demo', 'public': False, 'persistent': False}

    return app


def factory() -> FastAPI:
    return create_demo_app()
