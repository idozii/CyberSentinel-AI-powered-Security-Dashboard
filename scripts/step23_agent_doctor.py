"""Local-only preflight for the installable demo agent, without transmitting keys."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from urllib import request

from cybersentinel_agent.client import AgentError, NoRedirect, load_events

ORIGIN = 'http://127.0.0.1:8019'


def diagnose(input_file: Path | None = None, *, check_server: bool = False,
             key: str | None = None) -> dict:
    key = os.environ.get('CYBERSENTINEL_AGENT_KEY', '') if key is None else key
    result = {'mode': 'localhost-only', 'key_present': key.startswith('csd_') and len(key) >= 36,
              'server_checked': check_server, 'server_healthy': None,
              'events_validated': None, 'no_secrets_printed': True}
    if input_file is not None:
        if not result['key_present']:
            raise AgentError('Local demo key required to pseudonymize input log')
        result['events_validated'] = len(load_events(input_file, key, 25))
    if check_server:
        # Pin exact URL, no environment proxies, no redirects or external traffic.
        opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
        try:
            with opener.open(ORIGIN+'/health', timeout=3) as response:
                value = json.loads(response.read(512))
                result['server_healthy'] = (response.status == 200 and
                                           value.get('mode') == 'isolated-local-demo' and
                                           value.get('public') is False)
        except (OSError, ValueError):
            result['server_healthy'] = False
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description='Local demo agent readiness diagnosis')
    parser.add_argument('--input', type=Path)
    parser.add_argument('--check-server', action='store_true')
    args = parser.parse_args()
    try:
        result = diagnose(args.input, check_server=args.check_server)
    except (AgentError, OSError) as exc:
        parser.exit(2, f'Doctor failed: {exc}\n')
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['server_healthy'] is not False else 2


if __name__ == '__main__':
    raise SystemExit(main())
