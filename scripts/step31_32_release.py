"""In-process release rehearsal; never binds a public port or contacts cloud."""
from __future__ import annotations

import json

from fastapi.testclient import TestClient

from hosted_api.local_demo import DemoStore, create_demo_app
from scripts.step25_release import release_smoke
from scripts.step30_beta_gate import DEFAULT, assess
from scripts.step31_32_preflight import check


def rehearse() -> dict:
    preflight = check()
    earlier = release_smoke()
    with TestClient(create_demo_app(DemoStore(), enabled=True)) as client:
        pages = {name: client.get(path) for name, path in (
            ('dashboard', '/'), ('alerts', '/demo/alerts'),
            ('evaluation', '/demo/evaluation'), ('operations', '/demo/operations'),
            ('readiness', '/demo/readiness'), ('style', '/demo/assets/soc.css'),
        )}
        readiness = assess(json.loads(DEFAULT.read_text(encoding='utf-8')))
        checks = {
            'step25_e2e_still_passes': earlier['status'] == 'pass',
            'step31_preflight': preflight['status'] == 'pass',
            'pages_render': all(resp.status_code == 200 for resp in pages.values()),
            'navigation_present': all('CYBERSENTINEL' in pages[key].text
                                      for key in ('dashboard', 'alerts', 'evaluation', 'operations', 'readiness')),
            'first_party_styles': 'text/css' in pages['style'].headers['content-type'],
            'strict_csp': "style-src 'self'" in pages['dashboard'].headers['content-security-policy'],
            'no_live_secrets': 'postgresql://' not in pages['dashboard'].text,
            'public_beta_still_blocked': readiness['status'] == 'blocked' and
                                         not readiness['authorization_to_deploy_publicly'],
        }
    return {'status': 'pass' if all(checks.values()) else 'fail', 'checks': checks,
            'scope': 'Local SOC UI v2 release rehearsal; no public SaaS claims',
            'beta_gate': 'blocked'}


def main() -> int:
    result = rehearse()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
