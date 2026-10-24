"""Static contract checks for offline Step 20 synthetic evaluation."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    'hosted_api/demo_evaluation.py',
    'scripts/step20_evaluate.py',
    'scripts/step20_preflight.py',
    'tests/test_step20_evaluation.py',
    'docs/HUONG_DAN_BUOC_20.md',
    'docs/STEP20_EVALUATION_LIMITATIONS.md',
)


def check(root: Path = ROOT) -> dict:
    missing = [p for p in REQUIRED if not (root / p).is_file()]
    if missing:
        return {'status': 'fail', 'missing': missing}
    evaluator = (root / 'hosted_api/demo_evaluation.py').read_text(encoding='utf-8')
    cli = (root / 'scripts/step20_evaluate.py').read_text(encoding='utf-8')
    portal = (root / 'hosted_api/local_demo.py').read_text(encoding='utf-8')
    ci = (root / '.github/workflows/ci.yml').read_text(encoding='utf-8')
    checks = {
        'fresh_in_memory_case_store': 'db = DemoStore()' in evaluator,
        'real_ingest_code_path': 'db.ingest(key, db.domain_id, batch)' in evaluator,
        'dedup_replay_verification': "replay['duplicates']" in evaluator,
        'confusion_matrix_and_synthetic_labels': "'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0" in evaluator,
        'limits_clearly_disclosed': 'not a real-world attack dataset' in evaluator,
        'cli_refuses_overwrite': 'os.O_EXCL' in cli and 'exist_ok=False' in cli,
        'cli_prevents_repo_exports': 'is_relative_to(ROOT)' in cli,
        'demo_page_exists': "@app.get('/demo/evaluation')" in portal,
        'demo_origin_boundary_preserved': "response.headers['Referrer-Policy'] = 'same-origin'" in portal,
        'ci_evaluation_tests': 'test_step20_evaluation.py -v' in ci,
        'ci_evaluation_preflight': 'python -m scripts.step20_preflight' in ci,
    }
    return {'status': 'pass' if all(checks.values()) else 'fail',
            'checks': checks,
            'limitations': 'Static checks only; synthetic results do not establish production detection quality.'}


def main() -> int:
    result = check()
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
