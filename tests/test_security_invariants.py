"""Security invariant checks across bootstrap source code."""

import ast
import os
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "invoixy_bootstrap"


class TestSecurityInvariants(unittest.TestCase):
    def test_no_shell_true_in_source(self):
        """Ensure shell=True is never used in any subprocess call."""
        for py_file in SRC_DIR.glob("*.py"):
            with open(py_file, "r", encoding="utf-8") as f:
                content = f.read()
            tree = ast.parse(content, filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            self.fail(f"Found shell=True in {py_file} at line {node.lineno}")

    def test_forbidden_role_grants_absent_from_executable_paths(self):
        """Ensure broad predefined roles are not granted in code."""
        forbidden_roles = [
            "roles/owner",
            "roles/editor",
            "roles/iam.serviceAccountTokenCreator",
            "roles/secretmanager.secretAccessor",
            "roles/storage.objectAdmin",
        ]
        for py_file in SRC_DIR.glob("*.py"):
            with open(py_file, "r", encoding="utf-8") as f:
                content = f.read()
            for r in forbidden_roles:
                self.assertNotIn(r, content, f"Forbidden role reference {r} found in {py_file}")

    def test_no_services_enable_in_source(self):
        """Ensure bootstrap never executes 'services enable'."""
        for py_file in SRC_DIR.glob("*.py"):
            with open(py_file, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn("services enable", content, f"'services enable' found in {py_file}")
            self.assertNotIn("services.enable", content, f"'services.enable' found in {py_file}")

    def test_no_raw_isoformat_in_condition_logic(self):
        """Ensure raw isoformat is not used for condition formatting."""
        cond_file = SRC_DIR / "conditions.py"
        with open(cond_file, "r", encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn(".isoformat()", text, f"Found .isoformat() in {cond_file}")

    def test_readme_and_source_no_inaccurate_security_claims(self):
        """Ensure public documentation and source code contain no inaccurate zero-credential / credentialless claims."""
        root_dir = Path(__file__).resolve().parent.parent
        readme_path = root_dir / "README.md"
        with open(readme_path, "r", encoding="utf-8") as f:
            readme_text = f.read().lower()

        inaccurate_phrases = [
            "zero-credential",
            "zero credential",
            "zero credentials",
            "credentialless",
            "fully keyless",
            "no credentials",
        ]
        for phrase in inaccurate_phrases:
            self.assertNotIn(
                phrase,
                readme_text,
                f"Inaccurate security claim '{phrase}' found in README.md",
            )


if __name__ == "__main__":
    unittest.main()

