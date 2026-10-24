"""Read-only Step 14 staging template and remote agent security preflight.

This is a source-level smoke check, not a substitute for live Caddy validation,
firewall policy, TLS certificate checks, secret scanning, or a penetration test.
"""
from __future__ import annotations

import json
from pathlib import Path


def audit(repo: Path) -> dict[str, object]:
    root = Path(repo)
    p = root / 'deploy/Caddyfile.ingest.example'
    caddy = p.read_text(encoding='utf-8')
    owner = (root / 'deploy/cybersentinel-owner.service.example').read_text(encoding='utf-8')
    ingest = (root / 'deploy/cybersentinel-ingest.service.example').read_text(encoding='utf-8')
    flags = {
        'only_agent_ingest_path_in_proxy': 'path /agent/v1/ingest' in caddy and 'method POST' in caddy,
        'default_404': 'respond "Not found" 404' in caddy,
        'ingest_upstream_only': 'reverse_proxy 127.0.0.1:8004' in caddy and 'reverse_proxy 127.0.0.1:8002' not in caddy,
        'bounded_request_body': 'max_size 32KB' in caddy,
        'private_owner_listener': '--host 127.0.0.1 --port 8002' in owner,
        'private_ingest_listener': '--host 127.0.0.1 --port 8004' in ingest,
        'shared_database': 'CYBERSENTINEL_OWNER_DB=/var/lib/cybersentinel/owner.sqlite3' in owner and 'CYBERSENTINEL_OWNER_DB=/var/lib/cybersentinel/owner.sqlite3' in ingest,
        'dedicated_ingest_app': 'owner_api.ingest_only:app' in ingest,
    }
    return {'status': 'pass' if all(flags.values()) else 'fail', 'checks': flags,
            'limitations': 'Static template checks only, does not validate live hosting or Caddy parsing.'}


def main() -> int:
    result = audit(Path(__file__).resolve().parents[1])
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'pass' else 2


if __name__ == '__main__':
    raise SystemExit(main())
