"""Unit tests for Gcloud adapter logic, non-interactive flags, and API checks."""

import subprocess
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from invoixy_bootstrap.gcloud import FakeGcloudAdapter, RealGcloudAdapter, _compare_semver
from invoixy_bootstrap.models import BootstrapStatus


class TestGcloudAdapter(unittest.TestCase):
    def test_semver_comparisons(self):
        self.assertEqual(_compare_semver("450.0.0", "263.0.0"), 1)
        self.assertEqual(_compare_semver("263.0.0", "263.0.0"), 0)
        self.assertEqual(_compare_semver("200.0.0", "263.0.0"), -1)
        self.assertEqual(_compare_semver("263.1.0", "263.0.0"), 1)

    def test_real_gcloud_adapter_non_interactive_invariants(self):
        adapter = RealGcloudAdapter(gcloud_path="dummy_gcloud")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="{}", stderr="")

            # Test _run_cmd env and stdin
            adapter._run_cmd(["test", "cmd"], timeout=10)
            mock_run.assert_called_once()
            _, kwargs = mock_run.call_args
            self.assertFalse(kwargs.get("shell", True))
            self.assertEqual(kwargs.get("stdin"), subprocess.DEVNULL)
            self.assertEqual(kwargs.get("env", {}).get("CLOUDSDK_CORE_DISABLE_PROMPTS"), "1")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="{}", stderr="")
            # 1. create_custom_role contains --quiet
            adapter.create_custom_role("proj", "RoleV1", "Title", "Desc", "GA", ["p1"])
            cmd_args = mock_run.call_args[0][0]
            self.assertIn("--quiet", cmd_args)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="{}", stderr="")
            # 2. add_iam_policy_binding contains --quiet
            adapter.add_iam_policy_binding("proj", "RoleV1", "user:a@b.com", "Title", "Expr", "Desc")
            cmd_args = mock_run.call_args[0][0]
            self.assertIn("--quiet", cmd_args)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="{}", stderr="")
            # 3. remove_iam_policy_binding contains --quiet
            adapter.remove_iam_policy_binding("proj", "RoleV1", "user:a@b.com", "Title", "Expr", "Desc")
            cmd_args = mock_run.call_args[0][0]
            self.assertIn("--quiet", cmd_args)

    def test_fake_gcloud_adapter_lifecycle(self):
        adapter = FakeGcloudAdapter(version="450.0.0")
        ver_ok, ver_str = adapter.get_version()
        self.assertTrue(ver_ok)

        # Service API check
        st, is_en = adapter.check_service_enabled("test-proj", "iam.googleapis.com")
        self.assertEqual(st, BootstrapStatus.AUTHORIZED)
        self.assertTrue(is_en)

        # Role creation
        status, _ = adapter.describe_custom_role("test-proj", "InvoixySecurityAuditorV1", "fp123")
        self.assertEqual(status, BootstrapStatus.ROLE_MISSING)

        ok, err = adapter.create_custom_role("test-proj", "InvoixySecurityAuditorV1", "Title", "Desc", "GA", ["perm.a", "perm.b"])
        self.assertTrue(ok)

        # Binding creation
        now = datetime(2026, 8, 25, 12, 0, 0, tzinfo=timezone.utc)
        ok, err = adapter.add_iam_policy_binding(
            "test-proj",
            "InvoixySecurityAuditorV1",
            "serviceAccount:sa@invoixy.iam.gserviceaccount.com",
            "invoixy-security-review-v1-INV-GCP-2026-000001",
            'request.time < timestamp("2026-08-25T20:00:00Z")',
            "Desc",
        )
        self.assertTrue(ok)

        # Verify binding retrieval
        b_status, bindings = adapter.get_invoixy_bindings(
            "test-proj",
            "InvoixySecurityAuditorV1",
            "serviceAccount:sa@invoixy.iam.gserviceaccount.com",
            clock_now=now,
        )
        self.assertEqual(len(bindings), 1)
        self.assertFalse(bindings[0].is_expired)


if __name__ == "__main__":
    unittest.main()
