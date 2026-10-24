"""Read-only checks for a CyberSentinel source-control release.

Verifies required source/docs and rejects obvious tracked runtime artifacts.
This is not a full secret scanner or production security audit.
Run from the repository root: python -m scripts.release_audit
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path, PurePosixPath

REQUIRED_FILES = (
    "README.md",
    ".gitignore",
    ".github/workflows/ci.yml",
    "requirements-ml.txt",
    "requirements-dashboard.txt",
    "simulations/docker-compose.yml",
    "simulations/nginx/default.conf",
    "scripts/attack_replay.py",
    "scripts/build_labeled_dataset.py",
    "scripts/build_window_features.py",
    "scripts/train_detector.py",
    "scripts/audit_detector_robustness.py",
    "scripts/release_audit.py",
    "dashboard_api/main.py",
    "dashboard_api/store.py",
    "dashboard/app.py",
    "docs/HUONG_DAN_BUOC_4.md",
    "docs/HUONG_DAN_BUOC_5.md",
    "docs/HUONG_DAN_BUOC_6.md",
    "docs/HUONG_DAN_BUOC_7.md",
    "docs/HUONG_DAN_BUOC_8.md",
    "docs/PROJECT_ARCHITECTURE.md",
    "docs/EXPERIMENT_RESULTS.md",
    "docs/REPRODUCIBILITY.md",
    "docs/SECURITY_AND_LIMITATIONS.md",
    "docs/PORTFOLIO_DEMO.md",
    "owner_api/__init__.py",
    "owner_api/main.py",
    "owner_api/store.py",
    "owner_api/dns_verify.py",
    "owner_portal/app.py",
    "requirements-owner.txt",
    "docs/HUONG_DAN_BUOC_10.md",
    "docs/OWNER_PLATFORM_ROADMAP.md",
    "owner_api/telemetry.py",
    "cybersentinel_agent/__init__.py",
    "cybersentinel_agent/client.py",
    "cybersentinel_agent/cli.py",
    "scripts/normalize_dashes.py",
    "tests/test_step11_agent.py",
    "docs/HUONG_DAN_BUOC_11.md",
    "docs/OWNER_AGENT_SECURITY.md",
    "pyproject.toml",
)
REQUIRED_GITIGNORE = (
    ".venv/",
    ".env",
    "simulations/runtime/logs/",
    "simulations/runtime/raw/",
    "simulations/runtime/processed/",
    "simulations/runtime/owner/",
)
SERIALIZED_SUFFIXES = (".joblib", ".pkl", ".pickle", ".p12", ".pem", ".key")


def unsafe_tracked_path(raw: str) -> bool:
    """Flag likely accidental secrets/models/logs already in git's index."""
    name = PurePosixPath(raw.replace("\\", "/"))
    parts = name.parts
    basename = name.name.lower()
    if not parts:
        return False
    if any(part in (".venv", "venv", "__pycache__") for part in parts):
        return True
    if basename == ".env" or (basename.startswith(".env.") and basename != ".env.example"):
        return True
    if any(part.endswith(".egg-info") for part in parts) or "build" in parts or "dist" in parts:
        return True
    if basename.endswith(SERIALIZED_SUFFIXES) or basename.endswith(".pyc"):
        return True
    if len(parts) >= 3 and parts[:2] == ("simulations", "runtime") and parts[2] in ("logs", "raw", "processed", "owner"):
        return True
    return False


def tracked_paths(repo_root: Path) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"], cwd=repo_root,
            capture_output=True, check=True, timeout=15,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ValueError("Git index unavailable; run from a checked-out repository") from exc
    return [path.decode("utf-8", errors="replace") for path in result.stdout.split(b"\x00") if path]


def audit_release(repo_root: Path) -> dict[str, object]:
    """Validate local source tree and Git index; never modify any files."""
    root = Path(repo_root).resolve()
    missing = []
    for relative in REQUIRED_FILES:
        file = root / relative
        if not file.is_file() or not file.resolve().is_relative_to(root):
            missing.append(relative)
    if missing:
        raise ValueError("Missing required release files: " + ", ".join(missing))

    ignore = (root / ".gitignore").read_text(encoding="utf-8")
    lines = {line.strip() for line in ignore.splitlines() if line.strip() and not line.lstrip().startswith("#")}
    missing_patterns = [pattern for pattern in REQUIRED_GITIGNORE if pattern not in lines]
    if missing_patterns:
        raise ValueError("Missing runtime/secret ignore rules: " + ", ".join(missing_patterns))

    paths = tracked_paths(root)
    prohibited = sorted(path for path in paths if unsafe_tracked_path(path))
    if prohibited:
        raise ValueError("Unsafe tracked artifact path(s): " + ", ".join(prohibited))

    return {
        "status": "pass",
        "check": "source-layout-and-obvious-tracked-artifacts",
        "required_files_present": len(REQUIRED_FILES),
        "tracked_files_checked": len(paths),
        "unsafe_tracked_paths": 0,
        "limitations": "Not a secret scanner, SAST tool, privacy audit, or proof of production security.",
    }


def main() -> int:
    try:
        result = audit_release(Path(__file__).resolve().parents[1])
    except (ValueError, UnicodeError) as exc:
        print(json.dumps({"status": "fail", "reason": str(exc)}, indent=2))
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
