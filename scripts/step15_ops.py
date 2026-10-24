"""CLI for local/private owner SQLite operations (no public endpoints)."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from owner_api.operations import OperationsError, backup, inspect, retention, verify_restore

DEFAULT_DB = Path("simulations/runtime/owner/owner_local.sqlite3")
DEFAULT_BACKUPS = Path("simulations/runtime/owner/backups")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CyberSentinel private owner DB operations")
    parser.add_argument("action", choices=["inspect", "backup", "restore-check", "retention"])
    parser.add_argument("--db", type=Path, default=Path(os.environ.get("CYBERSENTINEL_OWNER_DB", DEFAULT_DB)))
    parser.add_argument("--backup-dir", type=Path, default=DEFAULT_BACKUPS)
    parser.add_argument("--backup-file", type=Path, help="Backup file to test, never overwrites live DB")
    parser.add_argument("--apply", action="store_true", help="Actually delete old data for retention")
    args = parser.parse_args(argv)
    try:
        if args.action == "inspect":
            result = inspect(args.db)
        elif args.action == "backup":
            result = backup(args.db, args.backup_dir)
        elif args.action == "restore-check":
            if not args.backup_file:
                parser.error("restore-check requires --backup-file")
            result = verify_restore(args.backup_file)
        else:
            result = retention(args.db, apply=args.apply)
    except (OperationsError, OSError, ValueError, __import__('sqlite3').DatabaseError) as exc:
        print(json.dumps({"status": "error", "reason": str(exc)}, indent=2))
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
