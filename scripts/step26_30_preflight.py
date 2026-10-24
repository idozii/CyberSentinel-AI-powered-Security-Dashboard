"""Fail-fast local packaging/readiness checks for Steps 26-30."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    'deployment/step26/Dockerfile', 'deployment/step26/compose.smoke.yml',
    'deployment/step26/requirements-smoke.txt',
    'deployment/step30/beta_evidence.example.json', '.dockerignore',
    'scripts/step27_tenant_audit.py', 'scripts/step29_reliability_drill.py',
    'scripts/step30_beta_gate.py', 'scripts/step26_30_preflight.py',
    'scripts/step26_30_release.py', 'tests/test_step26_30_fasttrack.py',
    'docs/HUONG_DAN_BUOC_26_30.md', 'docs/STEP26_30_SECURITY_BOUNDARIES.md',
    'docs/BETA_GO_NO_GO.md',
)


def check(root: Path = ROOT) -> dict:
    missing = [p for p in REQUIRED if not (root/p).is_file()]
    if missing:
        return {'status': 'fail', 'missing': missing}
    compose = (root/'deployment/step26/compose.smoke.yml').read_text()
    dockerfile = (root/'deployment/step26/Dockerfile').read_text()
    ignore = (root/'.dockerignore').read_text()
    ci = (root/'.github/workflows/ci.yml').read_text()
    demo = (root/'hosted_api/local_demo.py').read_text()
    evidence = json.loads((root/'deployment/step30/beta_evidence.example.json').read_text())
    checks = {
        'docker_network_disabled': 'network_mode: none' in compose,
        'no_docker_port_mapping': 'ports:' not in compose and 'network_mode: host' not in compose,
        'readonly_container': 'read_only: true' in compose,
        'restricted_container': 'no-new-privileges:true' in compose and 'cap_drop:' in compose and 'user: "10001:10001"' in compose,
        'non_root_image': 'USER 10001:10001' in dockerfile,
        'image_has_no_public_listener': 'scripts.step25_release' in dockerfile and 'EXPOSE ' not in dockerfile,
        'secrets_excluded_from_image': '.env' in ignore and '*.key' in ignore and 'simulations/runtime' in ignore,
        'demo_opt_in_unchanged': "DEMO_FLAG = 'CYBERSENTINEL_LOCAL_DEMO'" in demo,
        'safe_metrics_endpoint': "@app.get('/demo/operations.json')" in demo and 'operations_snapshot' in demo,
        'review_gate_fails_closed': all(value is False for value in evidence.values()),
        'ci_regression': 'python -m scripts.step26_30_release' in ci,
        'ci_live_rls_read_only': 'python -m scripts.step27_tenant_audit --live' in ci,
    }
    return {'status':'pass' if all(checks.values()) else 'fail',
            'checks': checks,
            'limitations': 'Static checks are not a penetration test, Docker build, cloud configuration review or beta approval.'}


def main() -> int:
    report = check()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
