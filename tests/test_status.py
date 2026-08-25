"""Unit tests for status inspection states."""

import unittest
from datetime import datetime, timezone

from invoixy_bootstrap.contract import load_auditor_contract
from invoixy_bootstrap.gcloud import FakeGcloudAdapter
from invoixy_bootstrap.models import BootstrapStatus
from invoixy_bootstrap.planner import BootstrapPlanner


class TestStatus(unittest.TestCase):
    def setUp(self):
        self.contract = load_auditor_contract()
        self.clock_dt = datetime(2026, 8, 25, 10, 0, 0, tzinfo=timezone.utc)
        self.clock = lambda: self.clock_dt

    def test_status_not_authorized_when_no_binding(self):
        adapter = FakeGcloudAdapter()
        planner = BootstrapPlanner(gcloud_adapter=adapter, contract=self.contract, clock=self.clock)
        res = planner.status("test-proj", "INV-GCP-2026-000001")
        self.assertEqual(res.result, BootstrapStatus.NOT_AUTHORIZED)

    def test_status_authorized_when_valid_binding(self):
        adapter = FakeGcloudAdapter()
        adapter.create_custom_role(
            "test-proj",
            self.contract.role_id,
            self.contract.title,
            self.contract.description,
            self.contract.stage,
            self.contract.included_permissions,
        )
        adapter.add_iam_policy_binding(
            "test-proj",
            self.contract.role_id,
            self.contract.scanner_member,
            "invoixy-security-review-v1-INV-GCP-2026-000001",
            'request.time < timestamp("2026-08-25T18:00:00Z")',
            "Desc",
        )
        planner = BootstrapPlanner(gcloud_adapter=adapter, contract=self.contract, clock=self.clock)
        res = planner.status("test-proj", "INV-GCP-2026-000001")
        self.assertEqual(res.result, BootstrapStatus.AUTHORIZED)

    def test_status_expired_binding_present(self):
        adapter = FakeGcloudAdapter()
        adapter.create_custom_role(
            "test-proj",
            self.contract.role_id,
            self.contract.title,
            self.contract.description,
            self.contract.stage,
            self.contract.included_permissions,
        )
        # Expiry is in past (09:00 vs current clock 10:00)
        adapter.add_iam_policy_binding(
            "test-proj",
            self.contract.role_id,
            self.contract.scanner_member,
            "invoixy-security-review-v1-INV-GCP-2026-000001",
            'request.time < timestamp("2026-08-25T09:00:00Z")',
            "Desc",
        )
        planner = BootstrapPlanner(gcloud_adapter=adapter, contract=self.contract, clock=self.clock)
        res = planner.status("test-proj", "INV-GCP-2026-000001")
        self.assertEqual(res.result, BootstrapStatus.EXPIRED_BINDING_PRESENT)


if __name__ == "__main__":
    unittest.main()
