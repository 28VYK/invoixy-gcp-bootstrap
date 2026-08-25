"""Unit tests for Gcloud adapter logic and semver comparisons."""

import unittest
from datetime import datetime, timezone

from invoixy_bootstrap.gcloud import FakeGcloudAdapter, _compare_semver
from invoixy_bootstrap.models import BootstrapStatus


class TestGcloudAdapter(unittest.TestCase):
    def test_semver_comparisons(self):
        self.assertEqual(_compare_semver("450.0.0", "263.0.0"), 1)
        self.assertEqual(_compare_semver("263.0.0", "263.0.0"), 0)
        self.assertEqual(_compare_semver("200.0.0", "263.0.0"), -1)
        self.assertEqual(_compare_semver("263.1.0", "263.0.0"), 1)

    def test_fake_gcloud_adapter_lifecycle(self):
        adapter = FakeGcloudAdapter(version="450.0.0")
        ver_ok, ver_str = adapter.get_version()
        self.assertTrue(ver_ok)

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
