"""Cloud-free final portfolio evidence gate and offline recruiter pack.

This never starts hosted services or changes data, metrics, database or Auth0.
The automated gate never declares a human-reviewed portfolio 100% complete.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    'LICENSE', 'README.md', 'dashboard/public_app.py',
    'dashboard/public_data.py', 'dashboard/public_metrics.json',
    'docs/EXPERIMENT_RESULTS.md', 'docs/PORTFOLIO_DEMO.md',
    'docs/REPRODUCIBILITY.md', 'docs/ZERO_COST_PORTFOLIO_RELEASE.md',
    'docs/PORTFOLIO_RECRUITER_PACK.md',
    'docs/PORTFOLIO_100_ACCEPTANCE.md',
    'scripts/zero_cost_portfolio.py',
    'scripts/portfolio_finalizer.py',
    'tests/test_portfolio_finalizer.py',
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _metrics(root: Path) -> dict:
    # Import the existing validator rather than inventing a second schema.
    from dashboard.public_data import validate_public_metrics
    file = root / 'dashboard/public_metrics.json'
    if file.is_symlink():
        raise ValueError('Evidence must be a regular file, not a symlink')
    data = json.loads(file.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ValueError('Evidence must be a JSON object')
    return validate_public_metrics(data)


def evaluate(root: Path = ROOT) -> dict:
    root = root.resolve()
    missing = [name for name in REQUIRED if not (root / name).is_file()]
    wf = root / '.github/workflows/ci.yml'
    workflow = wf.read_text(encoding='utf-8') if wf.is_file() else ''
    readme_file = root / 'README.md'
    readme = readme_file.read_text(encoding='utf-8') if readme_file.is_file() else ''
    checks = {
        'required_source_and_docs': not missing,
        'ci_final_tests_registered': 'test_portfolio_finalizer.py -v' in workflow,
        'previous_zero_cost_tests_preserved': 'test_zero_cost_portfolio.py -v' in workflow,
        'readme_has_final_guide': 'docs/PORTFOLIO_100_ACCEPTANCE.md' in readme,
        'license_present': (root / 'LICENSE').is_file(),
        'offline_showcase_present': (root / 'scripts/zero_cost_portfolio.py').is_file(),
    }
    result = {}
    try:
        data = _metrics(root)
        s = data['source']
        m = data['test']['isolation_forest']
        scan = data['test']['attack_scenarios']['Path scanning']
        split = data['splits']
        checks['holdout_numbers_reconciled'] = (
            s['simulated_requests'] == 2678 and s['feature_windows'] == 160
            and split['test_attack'] == 24 and m['fn'] == 17 and m['tp'] == 7
            and m['tn'] == 8 and m['fp'] == 0
            and scan['detected'] == 0 and scan['total'] == 8
            and abs(m['recall'] - (m['tp'] / (m['tp'] + m['fn']))) < 0.0001
        )
        result = {
            'source':'committed synthetic experiment summary (2026-10-24)',
            'simulated_requests': s['simulated_requests'],
            'simulated_windows': s['feature_windows'],
            'holdout_attack_windows': split['test_attack'],
            'isolation_forest_tp': m['tp'],
            'isolation_forest_fn': m['fn'],
            'isolation_forest_recall': m['tp'] / (m['tp'] + m['fn']),
            'scan_detected': scan['detected'],
            'scan_total': scan['total'],
            'fixed_rule_holdout_f1': data['test']['fixed_rule']['f1'],
            'important_caveat': 'Synthetic, repeated templates and small holdout; no real-world detection guarantee.',
        }
    except (OSError, ValueError, KeyError, TypeError, ZeroDivisionError):
        checks['holdout_numbers_reconciled'] = False

    hashes = {}
    for rel in ('dashboard/public_metrics.json', 'docs/EXPERIMENT_RESULTS.md', 'LICENSE'):
        p = root / rel
        if p.is_file() and not p.is_symlink():
            hashes[rel] = sha256_file(p)
    # Explicit human checks cannot be verified from repository source or CI.
    manual = [
        'Fresh clone in a separate directory: run audit and demo, record exact commands and outcomes',
        'Capture four original dashboard screenshots with no secrets or personal data',
        'Record a 2-4 minute real demonstration and verify the video is accessible',
        'Publish and manually open a GitHub release, CI link and portfolio/demo URL',
        'Verify team attribution, personal contributions and interview answers',
    ]
    return {
        'status': 'automated_pass' if all(checks.values()) else 'blocked',
        'checks': checks,
        'missing_files': missing,
        'metrics': result,
        'evidence_sha256': hashes,
        'manual_acceptance_pending': manual,
        'portfolio_100_percent_certified_by_script': False,
        'production_saas_ready': False,
        'cloud_database_or_auth0_required': False,
    }


def render_files(report: dict) -> dict[str, str]:
    metrics = report['metrics']
    if report['status'] != 'automated_pass' or not metrics:
        raise RuntimeError('Automated portfolio evidence must pass before building a recruiter pack')
    check_table = '\n'.join(f"- [{'x' if ok else ' '}] {key}" for key, ok in report['checks'].items())
    pending = '\n'.join('- [ ] ' + item for item in report['manual_acceptance_pending'])
    hashes = '\n'.join(f'- `{path}`: `{digest}`' for path,digest in sorted(report['evidence_sha256'].items()))
    return {
        'FACT_SHEET.md': f'''# CyberSentinel - Verified Portfolio Fact Sheet

**Type:** Cloud-free, synthetic telemetry research showcase. Not production IDS or public SaaS.

**Evidence source:** `dashboard/public_metrics.json`, commit-tracked research summary dated 2026-10-24.

- Simulated HTTP requests: {metrics['simulated_requests']:,}
- Experiment windows: {metrics['simulated_windows']}
- Isolation Forest held-out attack detection: {metrics['isolation_forest_tp']}/{metrics['holdout_attack_windows']} ({100*metrics['isolation_forest_recall']:.2f}% recall)
- Missed held-out attack windows: {metrics['isolation_forest_fn']}
- Scanning attack windows detected: {metrics['scan_detected']}/{metrics['scan_total']}
- Fixed rule baseline holdout F1: {metrics['fixed_rule_holdout_f1']:.2f} on the synthetic benchmark, not generalized performance

**Limitations:** {metrics['important_caveat']}
The results are a recorded, user-reported local run; raw output is not committed. A green source audit does not independently reproduce the ML experiment.

## Source hashes (SHA-256)
{hashes}
''',
        'DEMO_SCRIPT.md': '''# CyberSentinel - 3-minute Demo Script

1. **00:00-00:30 Problem.** Explain why raw HTTP logs need provenance and behavioral aggregation.
2. **00:30-01:10 Architecture.** Show NGINX -> collector -> event/request-ID match -> 14 features -> models -> dashboard.
3. **01:10-02:00 Dashboard.** Start `python -m scripts.zero_cost_portfolio demo`, open Overview, Traffic and Model Evaluation. Show clearly labeled synthetic results.
4. **02:00-02:30 Critical finding.** Isolation Forest misses 17 of 24 attack windows and 8 of 8 scanning windows; explain the limits of rule baseline perfection.
5. **02:30-03:00 Engineering.** Show CI, the no-cloud audit and reproducibility documentation; distinguish disposable tenant-security proofs from production SaaS.

Do not show secrets, real customer logs or suggest that the static dashboard is real-time intrusion detection.
''',
        'CV_INTERVIEW.md': '''# CV and Interview Evidence (verify team authorship)

## Suggested bullets
- Built and evaluated a reproducible HTTP security-telemetry research pipeline using NGINX, Python, 14 behavioral features and run-aware synthetic experiments.
- Compared Isolation Forest with explainable rules; documented low attack recall (29.17% on 24 held-out simulated attack windows) and scanning failures rather than inflating results.
- Contributed to local FastAPI/Streamlit security dashboards, automated CI and disposable PostgreSQL tenant-isolation integration tests.

Edit each statement to match actual commits and contributions. This is a team repository; do not claim all work as individual.

## Be ready to answer
- Why does run-disjoint sampling not prove template-disjoint generalization?
- Why is 100% rule baseline F1 on synthetic data not a production guarantee?
- Why is an immutable verified DB tenant identity safer than request-set actor IDs?
- Why are Neon/Auth0 and public multi-tenant SaaS excluded from the no-cost release?
- What new dataset/splits would you use before publication?
''',
        'RELEASE_CHECKLIST.md': f'''# CyberSentinel - Portfolio Final Acceptance

## Machine-verifiable source criteria
{check_table}

## Human evidence required before saying portfolio is 100% ready
{pending}

## Suggested release procedure
- Ensure all GitHub CI jobs PASS on the final commit, including Python, Docker and disposable PostgreSQL.
- Verify from a **fresh clone** on a different directory/machine; do not reuse untracked runtime artifacts.
- Add scrubbed screenshots under `docs/images/` only after you capture real working UI.
- Create and publish a GitHub release/tag **only after the PR is merged**, noting exact commit and CI URL.
- Manually check every GitHub, Streamlit and video link in an incognito browser.
- Confirm repository LICENSE and attribution match the team's agreement.

**Automated source pass is not proof of successful human demo or 100% portfolio readiness.**
''',
        'EVIDENCE.json': json.dumps(report, indent=2, sort_keys=True) + '\n',
    }


def export_pack(output_dir: Path, report: dict, root: Path = ROOT) -> Path:
    path = output_dir.expanduser().absolute()
    repo = root.resolve()
    if path == repo or path.resolve().is_relative_to(repo):
        raise ValueError('Evidence pack must be outside the repository')
    if path.exists():
        raise FileExistsError('Output directory already exists; never overwrite evidence')
    if not path.parent.is_dir():
        raise ValueError('Parent output directory does not exist')
    files = render_files(report)
    path.mkdir(mode=0o700)
    try:
        for name, body in files.items():
            target = path / name
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                handle.write(body)
    except Exception:
        for item in path.iterdir():
            item.unlink()
        path.rmdir()
        raise
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description='Cloud-free, honest CyberSentinel recruiter handoff')
    parser.add_argument('--output-dir', type=Path, help='New directory OUTSIDE repo to export portfolio pack')
    args = parser.parse_args()
    report = evaluate()
    if args.output_dir:
        try:
            output = export_pack(args.output_dir, report)
            print('Created offline recruiter pack at ' + str(output), file=sys.stderr)
        except (RuntimeError, OSError, ValueError) as exc:
            parser.error(str(exc))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['status'] == 'automated_pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
