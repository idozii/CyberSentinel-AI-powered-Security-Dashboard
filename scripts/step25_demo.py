"""One command to run the isolated portfolio demo on loopback only."""
from __future__ import annotations

import os


def main() -> int:
    # Keep staging credentials out of the demonstration process entirely.
    sensitive = ('CYBERSENTINEL_PG_RUNTIME_DSN', 'CYBERSENTINEL_PG_MIGRATION_DSN',
                 'CYBERSENTINEL_AUTH0_CLIENT_SECRET')
    if any(os.environ.get(name) for name in sensitive):
        raise SystemExit('Run this demo from a clean terminal without Neon/Auth0 secrets')
    os.environ['CYBERSENTINEL_LOCAL_DEMO'] = '1'
    import uvicorn
    uvicorn.run('hosted_api.local_demo:factory', factory=True,
                host='127.0.0.1', port=8019, workers=1, access_log=False)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
