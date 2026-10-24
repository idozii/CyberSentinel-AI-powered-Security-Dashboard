"""Supplementary manually labeled robustness fixtures; Step 20/21 stay frozen."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from hosted_api.demo_evaluation import Scenario, evaluate, markdown_report

ROBUSTNESS_SCENARIOS = (
    Scenario('extra_failed_logins', 6, 'login', 401, ('repeated_login_failures',),
             explanation='A clear burst over the current threshold'),
    Scenario('benign_auth_errors', 5, 'login', 401,
             explanation='Possible legitimate authentication failures; manually labeled benign'),
    Scenario('missing_resources', 9, 'other', 404, ('http_404_burst',),
             explanation='Synthetic multi-request probing'),
    Scenario('benign_missing_assets', 8, 'other', 404,
             explanation='Broken website assets can resemble a scan'),
    Scenario('burst_of_server_errors', 6, 'api', 500, ('server_error_burst',),
             explanation='Synthetic service failures'),
    Scenario('maintenance_503', 5, 'api', 503,
             explanation='Maintenance faults are not necessarily attacks'),
    Scenario('traffic_above_threshold', 41, 'api', 200, ('request_volume_spike',),
             explanation='Synthetic high-rate request burst'),
    Scenario('legitimate_health_checks', 20, 'health', 200,
             explanation='Benign health polling below alert level'),
    Scenario('distributed_low_rate_login', 6, 'login', 401, ('repeated_login_failures',),
             source_split=(3, 3), explanation='Attack-like activity split by sources'),
    Scenario('api_401_not_login', 5, 'api', 401,
             explanation='HTTP 401 outside login route must not imply login rule'),
    Scenario('low_rate_account_attempts', 4, 'login', 401, ('repeated_login_failures',),
             explanation='Manually suspicious despite being below the threshold'),
)

ERROR_TAXONOMY = {
    'false_alarm': 'Benign 401, 404, maintenance or monitoring may exceed static thresholds.',
    'missed_low_rate': 'Per-source threshold rules may miss low-rate sequences.',
    'distributed_sources': 'Source-based windows may miss bursts split across source pseudonyms.',
    'limited_labels': 'Synthetic hand-assigned labels need independent human validation.',
    'unmeasured_ml': 'The machine learning component is not measured by this suite.',
}


def analyze(*, clock: float | None = None) -> dict:
    report = evaluate(scenarios=ROBUSTNESS_SCENARIOS, clock=clock)
    report['suite'] = 'CyberSentinel Step 24 additional synthetic failure analysis'
    report['label_provenance'] = 'Manually authored synthetic labels, not verified attacks'
    report['error_taxonomy'] = ERROR_TAXONOMY
    report['limitations'].append('This is a supplementary suite and does not replace the frozen Step 20/21 benchmark.')
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description='Offline labeled synthetic robustness analysis')
    parser.add_argument('--output-dir', type=Path)
    args = parser.parse_args()
    report = analyze()
    summary = {'scenarios': report['scenario_count'], 'metrics': report['metrics'],
               'manifest_sha256': report['manifest_sha256'],
               'label_provenance': report['label_provenance']}
    if args.output_dir:
        target = args.output_dir.expanduser().resolve()
        root = Path(__file__).resolve().parents[1]
        if target == root or target.is_relative_to(root):
            parser.error('Reports must be outside the Git repository')
        if target.exists():
            parser.error('Output directory already exists - no overwrites')
        target.mkdir(parents=True, exist_ok=False)
        (target / 'step24_robustness.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
        (target / 'step24_robustness.md').write_text(markdown_report(report).replace('Step 20 Synthetic Detection Evaluation', 'Step 24 Supplementary Synthetic Failure Analysis', 1))
        summary['reports_saved'] = True
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
