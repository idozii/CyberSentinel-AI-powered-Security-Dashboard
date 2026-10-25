"""Server-rendered, dependency-free SOC-style UI for the opt-in localhost demo.

Presentation only: no live queries, no authentication bypass, and no public routes.
All user/data-derived values must be escaped before insertion into HTML.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone

from owner_api.detection import RULES


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


NAV = (
    ('Overview', '/', 'overview', '◈'),
    ('Alert triage', '/demo/alerts', 'alerts', '◇'),
    ('Evaluation', '/demo/evaluation', 'evaluation', '▤'),
    ('Tuning lab', '/demo/tuning', 'tuning', '⌁'),
    ('Operations', '/demo/operations', 'operations', '▦'),
    ('Beta readiness', '/demo/readiness', 'readiness', '⬡'),
)


def _active(title: str) -> str:
    name = title.lower()
    if 'triage' in name or 'alert evidence' in name:
        return 'alerts'
    if 'evaluation' in name:
        return 'evaluation'
    if 'threshold' in name or 'tuning' in name:
        return 'tuning'
    if 'operations' in name:
        return 'operations'
    if 'readiness' in name:
        return 'readiness'
    return 'overview'


def page(title: str, content: str) -> str:
    """Renders an accessible layout; content is trusted server-generated markup."""
    key = _active(title)
    nav = ''.join(
        '<a class="nav-link'+(' is-active' if key == item_key else '')+'" href="'+href+'"'
        + (' aria-current="page"' if key == item_key else '') + '>'
        '<span class="nav-icon" aria-hidden="true">'+glyph+'</span>'
        '<span>'+esc(label)+'</span></a>'
        for label, href, item_key, glyph in NAV
    )
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta name="theme-color" content="#08101c">'
            '<title>'+esc(title)+' | CyberSentinel</title>'
            '<link rel="stylesheet" href="/demo/assets/soc.css">'
            '<script src="/demo/assets/soc.js" defer></script>'
            '</head><body><a class="skip-link" href="#content">Skip to content</a>'
            '<div class="app-layout"><aside class="sidebar" aria-label="Main navigation">'
            '<a class="brand" href="/"><span class="brand-mark" aria-hidden="true">⌁</span>'
            '<span><strong>CYBER<span class="brand-accent">SENTINEL</span></strong>'
            '<small>SECURITY OPERATIONS</small></span></a>'
            '<div class="sidebar-label">WORKSPACE</div><nav class="side-nav">'+nav+'</nav>'
            '<div class="side-bottom"><div class="environment">'
            '<span class="live-dot" aria-hidden="true"></span>'
            '<span><b>Local sandbox</b><small>127.0.0.1 · isolated</small></span></div>'
            '<p>Prototype environment<br>Not connected to production</p></div></aside>'
            '<div class="workspace"><header class="topbar">'
            '<div class="topbar-crumb"><span>Workspace</span><span class="crumb-slash">/</span>'
            '<strong>'+esc(title)+'</strong></div>'
            '<div class="topbar-actions"><span class="pill pill-blue">LOCAL DEMO</span>'
            '<a href="/health" class="health-link" title="Local health check">'
            '<span class="live-dot" aria-hidden="true"></span>System active</a></div>'
            '</header><main id="content" class="content">'
            '<div class="page-heading"><div><div class="eyebrow">CYBERSENTINEL / LOCAL WORKSPACE</div>'
            '<h1>'+esc(title)+'</h1></div>'
            '<a class="btn btn-muted refresh-link" href="" aria-label="Refresh this page">'
            '<span aria-hidden="true">↻</span> Refresh</a></div>'
            +content+'</main><footer class="footer">'
            '<span>CyberSentinel · Local Portfolio MVP · SOC UI v2</span>'
            '<span>Synthetic telemetry only · Ephemeral memory · Not public</span>'
            '</footer></div></div></body></html>')


def _stats_cell(name: str, value: object, note: str, symbol: str, tone: str = 'cyan') -> str:
    return ('<article class="stat-card"><div class="stat-card-top"><span class="stat-label">'
            +esc(name)+'</span><span class="stat-symbol tone-'+tone+'" aria-hidden="true">'
            +symbol+'</span></div><strong class="stat-value">'+esc(value)+'</strong>'
            '<span class="stat-note">'+esc(note)+'</span></article>')


def _activity_chart(overview: dict) -> str:
    bins = overview['activity']
    max_events = max((row['count'] for row in bins), default=0)
    rows = []
    for row in bins:
        level = 0 if max_events == 0 else max(1, round(row['count'] / max_events * 10)) if row['count'] else 0
        level = min(10, level)
        rows.append('<div class="chart-column" title="'+esc(row['time'])+' UTC · '
                    +esc(row['count'])+' events">'
                    '<span class="chart-number">'+esc(row['count'])+'</span>'
                    '<span class="chart-track"><span class="chart-bar bar-'+str(level)+'"></span></span>'
                    '<span class="chart-time">'+esc(row['time'])+'</span></div>')
    return ('<section class="panel chart-panel"><div class="panel-heading"><div>'
            '<span class="section-kicker">TELEMETRY</span><h2>Event activity</h2>'
            '<p>Last 12 minutes · UTC · synthetic data</p></div>'
            '<span class="panel-mark">12M WINDOW</span></div>'
            '<div class="activity-chart" role="img" aria-label="Event counts by minute over the last twelve minutes">'
            +''.join(rows)+'</div></section>')


def _status_breakdown(overview: dict) -> str:
    statuses = overview['http_status']
    all_count = sum(statuses.values())
    lines = []
    for k, label, tone in [('2xx', 'Success (2xx)', 'green'), ('3xx','Redirect (3xx)','blue'),
                           ('4xx', 'Client error (4xx)', 'yellow'), ('5xx','Server error (5xx)','red')]:
        count = statuses[k]
        level = 0 if all_count == 0 else min(10, max(1, round(count * 10 / all_count))) if count else 0
        lines.append('<div class="progress-row"><div class="progress-label">'
                     '<span class="legend-dot bg-'+tone+'"></span>'+label+'<strong>'+str(count)+'</strong></div>'
                     '<div class="progress-track"><span class="progress-fill fill-'+tone+' width-'+str(level)+'"></span></div></div>')
    return ('<section class="panel breakdown-panel"><div class="panel-heading"><div>'
            '<span class="section-kicker">TRAFFIC HEALTH</span><h2>Response breakdown</h2>'
            '<p>Events currently held in memory</p></div></div>'
            '<div class="breakdown">'+''.join(lines)+'</div>'
            '<div class="breakdown-note"><span class="live-dot" aria-hidden="true"></span>'
            'Bounded local event store · max 500 events</div></section>')


def dashboard(data: dict, csrf: str, message: str = '') -> str:
    overview = data['overview']
    opened = sum(a['status'] == 'open' for a in data['alerts'])
    severe = sum(a['severity'] == 'high' and a['status'] == 'open' for a in data['alerts'])
    out = [
        '<section class="hero"><div class="hero-copy"><div class="hero-label">'
        '<span class="live-dot" aria-hidden="true"></span> ISOLATED WORKSPACE · OPERATIONAL</div>'
        '<h2>Security visibility, <em>without the noise.</em></h2>'
        '<p>Monitor synthetic activity, investigate suspicious patterns, and validate detection '
        'rules in a safe localhost environment.</p>'
        '<div class="hero-actions"><a class="btn btn-primary" href="/demo/alerts">'
        'Investigate alerts <span aria-hidden="true">↗</span></a>'
        '<a class="btn btn-outline" href="/demo/evaluation">View evaluation</a></div></div>'
        '<div class="hero-emblem" aria-hidden="true"><div class="emblem-ring outer">'
        '<div class="emblem-ring inner"><span>⌁</span></div></div></div></section>',
        '<div class="stat-grid">',
        _stats_cell('Total events', f"{data['total_events']:,}", 'Synthetic HTTP telemetry','↝'),
        _stats_cell('Open alerts', opened, f'{data["total_alerts"]} total detected','!', 'amber'),
        _stats_cell('High severity', severe, 'Unacknowledged high-priority alerts', '⚑', 'red'),
        _stats_cell('Active agent', 'Key ready' if data['key_issued'] else 'Not set',
                    'Demo key present' if data['key_issued'] else 'Generate a demo key to start','◎','violet'),
        '</div><div class="analytics-grid">',
        _activity_chart(overview), _status_breakdown(overview),
        '</div><div class="section-row"><div><span class="section-kicker">INVESTIGATION</span>'
        '<h2>Recent detections</h2></div><a class="text-action" href="/demo/alerts">'
        'View all alerts <span aria-hidden="true">↗</span></a></div>',
    ]
    if data['alerts']:
        out.append('<div class="alert-list">')
        for alert in data['alerts'][:5]:
            severity = alert['severity']
            out.append('<a class="alert-row" href="/demo/alerts/'+esc(alert['id'])+'">'
                       '<span class="alert-icon severity-'+esc(severity)+'" aria-hidden="true">!</span>'
                       '<span class="alert-description"><strong>'+esc(alert['title'])+'</strong>'
                       '<small>'+esc(alert['rule_id'])+'</small></span>'
                       '<span class="severity-label severity-'+esc(severity)+'">'+esc(severity.upper())+'</span>'
                       '<span class="status-label">'+esc(alert['status'])+'</span>'
                       '<span class="alert-arrow" aria-hidden="true">↗</span></a>')
        out.append('</div>')
    else:
        out.append('<div class="empty-panel"><span class="empty-icon" aria-hidden="true">◎</span>'
                   '<div><strong>No alerts yet</strong><p>Run the synthetic NGINX agent to start seeing detections.</p></div>'
                   '<a class="btn btn-muted" href="/demo/alerts">Open triage</a></div>')
    out.append('<div class="secondary-grid"><section class="panel">'
               '<div class="panel-heading"><div><span class="section-kicker">INGESTION</span>'
               '<h2>Recent event stream</h2><p>Last 20 events · anonymized source hints</p></div></div>'
               '<div class="table-scroll"><table class="events-table"><thead><tr><th>HTTP</th><th>Category</th>'
               '<th>Source hint</th><th>Time (UTC)</th></tr></thead><tbody>')
    for ev in data['events'][:8]:
        code = int(ev['status_code'])
        kind = 'ok' if code < 400 else 'warn' if code < 500 else 'fail'
        stamp = datetime.fromtimestamp(ev['occurred_at'], timezone.utc).strftime('%H:%M:%S')
        out.append('<tr><td><span class="http-code '+kind+'">'+esc(code)+'</span></td>'
                   '<td>'+esc(ev['path_group'])+'</td><td class="mono">'+esc(ev['source_ref'][:12])+'</td>'
                   '<td>'+esc(stamp)+'</td></tr>')
    if not data['events']:
        out.append('<tr><td colspan="4" class="table-empty">No events received. Start your local agent to populate this view.</td></tr>')
    out.append('</tbody></table></div></section><section class="panel agent-panel">'
               '<div class="panel-heading"><div><span class="section-kicker">SETUP</span>'
               '<h2>Demo agent</h2><p>Single fake tenant · ephemeral session</p></div></div>'
               '<div class="agent-status"><span class="live-dot" aria-hidden="true"></span>'
               +('Key available' if data['key_issued'] else 'No key issued yet')+'</div>'
               '<label class="field-label">LOCAL DEMO DOMAIN ID</label>'
               '<div class="copy-field"><code>'+esc(data['domain_id'])+'</code>'
               '<button type="button" class="btn-copy" data-copy="'+esc(data['domain_id'])+'"'
               ' aria-label="Copy demo domain ID">Copy</button></div>'
               '<form class="agent-form" method="post" action="/demo/key">'
               '<input type="hidden" name="_csrf" value="'+esc(csrf)+'">'
               '<button class="btn btn-primary" type="submit">Generate new local demo key</button></form>'
               '<p class="danger-note">Generating a new key revokes the previous key and resets demo data.</p>')
    if message:
        out.append('<div class="token-display" role="status">'+message+'</div>')
    out.append('<div class="setup-help"><strong>Quick start</strong>'
               '<p>Generate a demo key, send synthetic NGINX logs using '
               '<code>cybersentinel-demo-agent</code>, then inspect alerts.</p>'
               '<a href="/demo/operations">Step 28 - local operational counters</a></div>'
               '</section></div><p class="disclaimer">'
               'Local Demo is isolated and memory-only. It does not ingest real user traffic, '
               'connect to Neon/Auth0, or authorize Internet exposure.</p>')
    return ''.join(out)
