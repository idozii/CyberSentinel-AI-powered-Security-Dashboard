"""Step 8 source-release contract checks (no network or Docker needed)."""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.release_audit import (
    REQUIRED_FILES, REQUIRED_GITIGNORE, audit_release, unsafe_tracked_path,
)


class Step8ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True, capture_output=True)
        for name in REQUIRED_FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("Release file.\n", encoding="utf-8")
        (self.root / ".gitignore").write_text("\n".join(REQUIRED_GITIGNORE) + "\n", encoding="utf-8")
        self._git_add()

    def _git_add(self):
        subprocess.run(["git", "add", "-A"], cwd=self.root, check=True, capture_output=True)

    def _force_add(self, path: str):
        subprocess.run(["git", "add", "-f", "--", path], cwd=self.root, check=True, capture_output=True)

    def test_clean_repository_passes(self):
        report = audit_release(self.root)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["required_files_present"], len(REQUIRED_FILES))
        self.assertEqual(report["unsafe_tracked_paths"], 0)

    def test_missing_documentation_is_rejected(self):
        (self.root / "docs/EXPERIMENT_RESULTS.md").unlink()
        with self.assertRaisesRegex(ValueError, "EXPERIMENT_RESULTS.md"):
            audit_release(self.root)

    def test_tracked_runtime_csv_is_rejected(self):
        f = self.root / "simulations/runtime/processed/training.csv"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("private,rows\n", encoding="utf-8")
        self._force_add("simulations/runtime/processed/training.csv")
        with self.assertRaisesRegex(ValueError, "Unsafe tracked"):
            audit_release(self.root)

    def test_tracked_model_is_rejected(self):
        f = self.root / "model.joblib"
        f.write_bytes(b"fake-model")
        self._force_add("model.joblib")
        with self.assertRaisesRegex(ValueError, "model.joblib"):
            audit_release(self.root)

    def test_tracked_env_secret_is_rejected(self):
        f = self.root / ".env.local"
        f.write_text("FAKE_TOKEN=not-real\n", encoding="utf-8")
        self._force_add(".env.local")
        with self.assertRaisesRegex(ValueError, ".env.local"):
            audit_release(self.root)

    def test_missing_gitignore_rule_is_rejected(self):
        (self.root / ".gitignore").write_text(".venv/\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Missing runtime/secret ignore rules"):
            audit_release(self.root)

    def test_false_positive_avoidance(self):
        self.assertFalse(unsafe_tracked_path(".env.example"))
        self.assertFalse(unsafe_tracked_path("simulations/runtime/.gitkeep"))
        self.assertFalse(unsafe_tracked_path("docs/EXPERIMENT_RESULTS.md"))
        self.assertTrue(unsafe_tracked_path("simulations/runtime/logs/access.log"))
        self.assertTrue(unsafe_tracked_path("scripts/__pycache__/a.pyc"))


if __name__ == "__main__":
    unittest.main()
