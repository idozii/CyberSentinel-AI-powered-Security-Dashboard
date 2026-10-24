"""Source-only operator staging preflight. Not a live security assessment."""
from __future__ import annotations

import json
from pathlib import Path


FILES = (
    "deploy/cybersentinel-portal.service.example",
    "deploy/cybersentinel-backup.service.example",
    "deploy/cybersentinel-backup.timer.example",
    "deploy/cybersentinel-retention.service.example",
    "deploy/cybersentinel-retention.timer.example",
    "deploy/Caddyfile.ingest.example",
    "deploy/cybersentinel-owner.service.example",
    "owner_api/operations.py",
    "scripts/step15_ops.py",
)


def audit(root: Path) -> dict:
    root = Path(root)
    missing = [x for x in FILES if not (root / x).is_file()]
    if missing:
        return {"status": "fail", "reason": "Missing operator files", "paths": missing}
    portal = (root / FILES[0]).read_text()
    backup = (root / FILES[1]).read_text()
    retain = (root / FILES[3]).read_text()
    caddy = (root / "deploy/Caddyfile.ingest.example").read_text()
    owner = (root / "deploy/cybersentinel-owner.service.example").read_text()
    checks = {
        "private_portal": "--server.address 127.0.0.1" in portal and "--server.port 8503" in portal,
        "portal_has_no_public_proxy": "reverse_proxy" not in portal and "--server.address 0.0.0.0" not in portal,
        "owner_local_only": "--host 127.0.0.1 --port 8002" in owner,
        "ingest_only_public_proxy": "reverse_proxy 127.0.0.1:8004" in caddy and "127.0.0.1:8503" not in caddy and "127.0.0.1:8002" not in caddy,
        "private_backup_path": "/var/lib/cybersentinel/backups" in backup and "-m scripts.step15_ops backup" in backup,
        "retention_explicit_apply": "-m scripts.step15_ops retention --apply" in retain,
        "backup_timer": "Unit=cybersentinel-backup.service" in (root / FILES[2]).read_text(),
        "retention_timer": "Unit=cybersentinel-retention.service" in (root / FILES[4]).read_text(),
        "manual_https_preflight": (root / "scripts/step14_preflight.py").is_file(),
    }
    return {"status": "pass" if all(checks.values()) else "fail", "checks": checks,
            "limitations": "Static templates only. Does not test VPS firewall, TLS, backup encryption, IdP or PostgreSQL."}


def main() -> int:
    result = audit(Path(__file__).resolve().parents[1])
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
