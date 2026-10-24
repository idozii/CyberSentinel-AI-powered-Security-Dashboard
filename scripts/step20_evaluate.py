"""Generate an offline, synthetic rule benchmark report; no network or secrets."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from hosted_api.demo_evaluation import evaluate, markdown_report

ROOT = Path(__file__).resolve().parents[1]


def _write_new(path: Path, data: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        handle.write(data)


def run(output_dir: Path | None = None) -> dict:
    report = evaluate()
    if output_dir is not None:
        directory = output_dir.expanduser().absolute()
        if directory.is_relative_to(ROOT) or directory.resolve().is_relative_to(ROOT):
            raise ValueError('Reports must be outside the Git repository')
        # Never overwrite a report or follow a pre-existing destination directory.
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        _write_new(directory / 'step20_evaluation.json', json.dumps(report, indent=2, sort_keys=True) + '\n')
        _write_new(directory / 'step20_evaluation.md', markdown_report(report))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description='Offline synthetic alert-quality evaluation; never real traffic')
    parser.add_argument('--output-dir', type=Path, help='New directory outside the repository for JSON and Markdown')
    args = parser.parse_args()
    try:
        result = run(args.output_dir)
    except (ValueError, OSError, RuntimeError) as exc:
        parser.error(str(exc))
    print(json.dumps({'status': 'pass', 'suite': result['suite'],
                      'scenario_count': result['scenario_count'],
                      'scenario_rule_pairs': result['scenario_rule_pairs'],
                      'metrics': result['metrics'],
                      'manifest_sha256': result['manifest_sha256'],
                      'output_directory': str(args.output_dir) if args.output_dir else None}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
