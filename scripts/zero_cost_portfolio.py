"""Zero-cloud portfolio release: audited static evidence and localhost SOC UI.

No database connection, Auth0 login, external telemetry, or hosted deployment.
The website checker is disabled when this command starts Streamlit.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MODE = 'static_research_summary'
OFFLINE_ENV = 'CYBERSENTINEL_OFFLINE_ONLY'


def read_evidence(root: Path = ROOT) -> dict:
    """Validate the committed aggregate fixture with the repository's parser."""
    from dashboard.public_data import validate_public_metrics
    source = root / 'dashboard/public_metrics.json'
    if not source.is_file() or source.is_symlink():
        raise ValueError('Missing or symlinked public metrics fixture')
    if source.stat().st_size > 512 * 1024:
        raise ValueError('Public metrics fixture exceeds size limit')
    data = json.loads(source.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ValueError('Public metrics must be a JSON object')
    validate_public_metrics(data)
    if data.get('display_mode') != EXPECTED_MODE:
        raise ValueError('Public showcase is not a static research summary')
    if 'controlled' not in str(data['source'].get('description', '')).lower():
        raise ValueError('Missing controlled experiment provenance')
    return data


def assess(root: Path = ROOT, *, full: bool = False) -> dict:
    """Run evidence and isolation checks. Full mode also runs local in-process MVP smoke."""
    checks: dict[str, bool] = {}
    missing = [p for p in ('dashboard/public_app.py', 'dashboard/public_data.py',
                           'dashboard/public_metrics.json', 'scripts/step25_release.py')
               if not (root / p).is_file()]
    checks['local_portfolio_files_present'] = not missing
    data: dict = {}
    try:
        data = read_evidence(root)
        checks['aggregate_evidence_validated'] = True
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        checks['aggregate_evidence_validated'] = False
    app_file = root / 'dashboard/public_app.py'
    app = app_file.read_text(encoding='utf-8') if app_file.is_file() else ''
    checks['offline_checker_is_disabled'] = ('if OFFLINE_ONLY:' in app
                                            and 'disabled=OFFLINE_ONLY' in app
                                            and 'page == "Website checker" and not OFFLINE_ONLY' in app)
    checks['public_view_does_not_import_staging'] = all(
        keyword not in app for keyword in ('from hosted_api', 'import hosted_api',
                                           'import owner_api', 'CYBERSENTINEL_PG_RUNTIME_DSN'))
    checks['no_managed_services_required'] = bool(checks['public_view_does_not_import_staging']
                                                   and checks['aggregate_evidence_validated'])
    smoke = None
    if full:
        if root != ROOT:
            raise ValueError('Full local demo smoke is supported only in the installed repository')
        try:
            from scripts.step25_release import release_smoke
            smoke = release_smoke()
            checks['in_process_mvp_smoke'] = smoke.get('status') == 'pass'
        except (ImportError, OSError, RuntimeError, ValueError, AssertionError):
            checks['in_process_mvp_smoke'] = False
    metrics = data.get('test', {}).get('isolation_forest', {}) if data else {}
    attacks = data.get('splits', {}).get('test_attack') if data else None
    results = {
        'simulated_requests': data.get('source', {}).get('simulated_requests') if data else None,
        'windows': data.get('source', {}).get('feature_windows') if data else None,
        'attack_windows': attacks,
        'detected_attack_windows': metrics.get('tp'),
        'missed_attack_windows': metrics.get('fn'),
        'isolation_forest_recall': metrics.get('recall'),
        'isolation_forest_f1': metrics.get('f1'),
        'scanning_windows_detected': data.get('test', {}).get('attack_scenarios', {}).get('Path scanning', {}).get('detected') if data else None,
    }
    return {
        'status': 'pass' if all(checks.values()) else 'blocked',
        'scope': 'local_static_research_portfolio',
        'checks': checks, 'missing': missing, 'measurements': results,
        'managed_database_required': False, 'auth0_required': False,
        'live_detection_claimed': False, 'production_saas_ready': False,
        'public_multi_tenant_beta_allowed': False,
        'limitations': [
            'Bundled results are user-reported controlled-lab observations, not production telemetry.',
            'Isolation Forest did not detect the recorded path-scanning holdout windows.',
            'Full smoke is an in-process synthetic flow, not evidence of a real deployed service.',
            'Static showcase links may lead to external sites if manually opened.',
            'This audit is not an independent security assessment or proof of zero network traffic.',
        ],
        'local_mvp_smoke': smoke if full else 'not_run (pass --full to verify)',
    }


def scrubbed_environment() -> dict[str, str]:
    """Allow only basic launch variables; do not pass cloud credentials to Streamlit."""
    keep = ('PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'LC_CTYPE',
            'VIRTUAL_ENV', 'TMPDIR', 'TMP', 'TEMP', 'SYSTEMROOT', 'WINDIR')
    result = {k: os.environ[k] for k in keep if k in os.environ}
    result[OFFLINE_ENV] = '1'
    result['STREAMLIT_BROWSER_GATHER_USAGE_STATS'] = 'false'
    return result


def demo_command(port: int) -> list[str]:
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('Expected an unprivileged TCP port 1024..65535')
    return [sys.executable, '-m', 'streamlit', 'run', 'dashboard/public_app.py',
            '--server.address', '127.0.0.1', '--server.port', str(port),
            '--server.headless', 'true', '--browser.gatherUsageStats', 'false',
            '--server.enableCORS', 'true', '--server.enableXsrfProtection', 'true']


def render_html(report: dict) -> str:
    """Self-contained, network-free evidence page; no external CSS/scripts."""
    m = report['measurements']
    safe = lambda x: html.escape(str(x), quote=True)
    done = int(m.get('detected_attack_windows') or 0)
    total = int(m.get('attack_windows') or 0)
    missed = int(m.get('missed_attack_windows') or 0)
    detected_pct = (100 * done / total) if total else 0
    items = ''.join('<li>'+safe(note)+'</li>' for note in report['limitations'])
    checks = ''.join('<tr><td>'+safe(k.replace('_', ' '))+'</td><td>'+('PASS' if v else 'BLOCKED')+'</td></tr>'
                     for k, v in report['checks'].items())
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberSentinel - Offline Research Evidence</title><style>
:root{{color-scheme:dark}}body{{margin:0;background:#0d1624;color:#e8f2fa;font:16px/1.55 system-ui,sans-serif}}
main{{max-width:920px;margin:auto;padding:32px 22px}}h1{{font-size:2.2rem;margin:.5rem 0}}p,li{{color:#b8c8d6}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:14px;margin:24px 0}}
.card{{padding:18px;background:#17253a;border:1px solid #32435b;border-radius:12px}}
.num{{font-size:1.8rem;font-weight:750;color:#b9e0fb}}.label{{font-size:.8rem;color:#a9bdd0}}
.bar{{height:18px;background:#4b2536;border-radius:8px;overflow:hidden}}.fill{{height:100%;width:{detected_pct:.2f}%;background:#199a8b}}
table{{border-collapse:collapse;width:100%}}td{{border-bottom:1px solid #34465d;padding:8px}}
.small{{font-size:.85rem;color:#a6bed1}}a{{color:#9edcff}}
</style></head><body><main><div class="small">PORTFOLIO / CONTROLLED LOCAL SIMULATION</div>
<h1>CyberSentinel: Research Evidence</h1><p>Offline, static evidence. Not a live intrusion detection system or security certification.</p>
<div class="cards"><div class="card"><div class="label">Simulated requests</div><div class="num">{safe(m.get('simulated_requests'))}</div></div>
<div class="card"><div class="label">60-second windows</div><div class="num">{safe(m.get('windows'))}</div></div>
<div class="card"><div class="label">Isolation Forest recall</div><div class="num">{detected_pct:.1f}%</div></div>
<div class="card"><div class="label">Missed attacks</div><div class="num">{missed} / {total}</div></div></div>
<h2>Holdout attack detection</h2><div class="bar"><div class="fill"></div></div>
<p>{done} detected, {missed} missed, out of {total} attack windows. The model missed every recorded path-scanning window.</p>
<h2>Release audit</h2><p>Status: <strong>{safe(report['status'].upper())}</strong>. Public multi-tenant beta: <strong>NO-GO</strong>.</p>
<table>{checks}</table><h2>Important limitations</h2><ul>{items}</ul>
<p class="small">Source: dashboard/public_metrics.json and docs/EXPERIMENT_RESULTS.md in the CyberSentinel repository.
All metrics describe the committed synthetic research summary. No remote data was requested to generate this page.</p>
</main></body></html>'''


def write_output(path: Path, report: dict, root: Path = ROOT) -> None:
    """Write new evidence outside repository only; never overwrite any file."""
    requested = path.expanduser()
    if requested.suffix.lower() not in ('.json', '.html'):
        raise ValueError('Output filename must end with .json or .html')
    target = requested.resolve()
    checkout = root.resolve()
    if target == checkout or target.is_relative_to(checkout):
        raise ValueError('Output must be outside the Git repository')
    if not target.parent.is_dir():
        raise ValueError('Output directory does not exist')
    body = (render_html(report) if target.suffix.lower() == '.html'
            else json.dumps(report, indent=2, sort_keys=True)+'\n')
    # Exclusive file creation; avoid overwriting and symlink tricks.
    with requested.open('x', encoding='utf-8') as fh:
        fh.write(body)


def main() -> int:
    cli = argparse.ArgumentParser(description='CyberSentinel cloud-free portfolio milestone')
    sub = cli.add_subparsers(dest='command', required=True)
    audit = sub.add_parser('audit', help='Validate bundled evidence and local portfolio boundaries')
    audit.add_argument('--full', action='store_true', help='Also execute Step 25 in-process local MVP smoke')
    audit.add_argument('--output', type=Path, help='Write new .json or .html report outside repository')
    demo = sub.add_parser('demo', help='Start Streamlit static research dashboard on localhost')
    demo.add_argument('--port', type=int, default=8501)
    args = cli.parse_args()
    if args.command == 'audit':
        result = assess(full=args.full)
        if args.output:
            try:
                write_output(args.output, result)
            except (OSError, ValueError) as exc:
                cli.error(str(exc))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result['status'] == 'pass' else 2
    result = assess()
    if result['status'] != 'pass':
        print(json.dumps({'status': 'blocked', 'checks': result['checks']}, sort_keys=True))
        return 2
    try:
        cmd = demo_command(args.port)
    except ValueError as exc:
        cli.error(str(exc))
    print('CyberSentinel static research demo: http://127.0.0.1:'+str(args.port), flush=True)
    print('External website checker disabled. Press Ctrl+C to stop.', flush=True)
    try:
        return subprocess.call(cmd, cwd=ROOT, env=scrubbed_environment())
    except KeyboardInterrupt:
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
