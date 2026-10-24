"""Replace Unicode em/en dashes in Git-tracked text with the plain hyphen-minus.

Does NOT rewrite ASCII '--' because CLI flags, operators, and Markdown syntax
use it. Avoids binary files and all ignored local runtime/user files.
"""
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def normalized(text: str) -> str:
    return text.replace("\u2014", "-").replace("\u2013", "-")


def update_tracked(root: Path, *, apply: bool = False) -> list[str]:
    result = subprocess.run(["git", "ls-files", "-z"], cwd=root,
                            capture_output=True, check=True, timeout=15)
    changed = []
    for raw in result.stdout.split(b"\x00"):
        if not raw:
            continue
        rel = raw.decode("utf-8", errors="strict")
        path = (root / rel)
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        if b"\x00" in data:
            continue
        try:
            before = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        after = normalized(before)
        if after != before:
            changed.append(rel)
            if apply:
                path.write_bytes(after.encode("utf-8"))
    return changed


def main() -> int:
    p = argparse.ArgumentParser(description="Check or normalize em/en dashes in tracked text files")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--apply", action="store_true", help="Rewrite tracked text files")
    g.add_argument("--check", action="store_true", help="Fail if tracked text contains Unicode em/en dashes")
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    changed = update_tracked(root, apply=args.apply)
    print(f"{'Updated' if args.apply else 'Found'} {len(changed)} tracked text files with Unicode dashes")
    for rel in changed:
        print("  " + rel)
    return 2 if args.check and changed else 0


if __name__ == "__main__":
    raise SystemExit(main())
