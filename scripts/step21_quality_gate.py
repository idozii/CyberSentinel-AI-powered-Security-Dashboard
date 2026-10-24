"""Offline synthetic quality gate and threshold-sensitivity export."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from hosted_api.demo_tuning import markdown_report, quality_gate
from scripts.step20_evaluate import ROOT, _write_new


def run(output_dir: Path | None = None) -> dict:
    result = quality_gate()
    if result['status'] != 'pass':
        return result
    if output_dir is not None:
        target = output_dir.expanduser().absolute()
        if target.is_relative_to(ROOT) or target.resolve().is_relative_to(ROOT):
            raise ValueError('Reports must be outside the Git repository')
        target.mkdir(mode=0o700, exist_ok=False, parents=False)
        _write_new(target / 'step21_tuning.json', json.dumps(result['experiment'], sort_keys=True, indent=2) + '\n')
        _write_new(target / 'step21_tuning.md', markdown_report(result['experiment']))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description='Step 21 synthetic tuning - never changes live thresholds')
    parser.add_argument('--output-dir', type=Path, help='NEW directory outside Git containing restricted JSON/MD reports')
    args = parser.parse_args()
    try:
        report = run(args.output_dir)
    except (ValueError, OSError, RuntimeError) as exc:
        parser.error(str(exc))
    experiment = report.get('experiment', {})
    print(json.dumps({
        'status': report['status'], 'checks': report['checks'],
        'candidate_count': experiment.get('candidate_count'),
        'baseline_thresholds': experiment.get('baseline_thresholds'),
        'candidate_thresholds': experiment.get('candidate_thresholds'),
        'baseline_validation_f1': experiment.get('baseline_validation', {}).get('metrics', {}).get('f1'),
        'candidate_validation_f1': experiment.get('candidate_validation', {}).get('metrics', {}).get('f1'),
        'live_config_changed': False, 'release_approved': False,
    }, indent=2))
    return 0 if report['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
