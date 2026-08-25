"""Unit tests for authorize mutation flow and partial failures."""

import unittest
from datetime import datetime, timezone

from invoixy_bootstrap.contract import load_auditor_contract
from invoixy_bootstrap.gcloud import FakeGcloudAdapter
from invoixy_bootstrap.models import BootstrapStatus
from invoixy_bootstrap.planner import BootstrapPlanner


class TestAuthorize(unittest.TestCase):
    def setUp(self):
        self.contract = load_auditor_contract()
        self.clock_dt = datetime(2026, 8, 25, 10, 0, 0, tzinfo=timezone.utc)
        self.clock = lambda: self.clock_dt

    def test_authorize_creates_role_and_binding(self):
        adapter = FakeGcloudAdapter()
        planner = BootstrapPlanner(gcloud_adapter=adapter, contract=self.contract, clock=self.clock)

        res = planner.authorize("test-proj", "INV-GCP-2026-000001", ttl_hours=8, auto_confirm=True)
        self.assertEqual(res.result, BootstrapStatus.AUTHORIZED)
        self.assertEqual(len(res.changes), 2)

        # Re-authorize same audit ID returns ALREADY_AUTHORIZED without extending
        res2 = planner.authorize("test-proj", "INV-GCP-2026-000001", ttl_hours=8, auto_confirm=True)
        self.assertEqual(res2.result, BootstrapStatus.ALREADY_AUTHORIZED)

    def test_authorize_cancelled_without_confirmation(self):
        adapter = FakeGcloudAdapter()
        planner = BootstrapPlanner(gcloud_adapter=adapter, contract=self.contract, clock=self.clock)

        res = planner.authorize("test-proj", "INV-GCP-2026-000001", ttl_hours=8, auto_confirm=False, confirm_callback=lambda p: False)
        self.assertEqual(res.result, BootstrapStatus.CANCELLED)
        self.assertEqual(len(adapter.call_history), 0)

    def test_authorize_handles_role_creation_failure(self):
        adapter = FakeGcloudAdapter()
        adapter.fail_role_creation = True
        planner = BootstrapPlanner(gcloud_adapter=adapter, contract=self.contract, clock=self.clock)

        res = planner.authorize("test-proj", "INV-GCP-2026-000001", ttl_hours=8, auto_confirm=True)
        self.assertEqual(res.result, BootstrapStatus.ROLE_CREATION_FAILED)

    def test_authorize_handles_role_created_binding_failure(self):
        adapter = FakeGcloudAdapter()
        adapter.fail_binding_addition = True
        planner = BootstrapPlanner(gcloud_adapter=adapter, contract=self.contract, clock=self.clock)

        res = planner.authorize("test-proj", "INV-GCP-2026-000001", ttl_hours=8, auto_confirm=True)
        self.assertEqual(res.result, BootstrapStatus.ROLE_CREATED_BINDING_FAILED)

    def test_authorize_handles_post_verification_failure(self):
        adapter = FakeGcloudAdapter()
        adapter.fail_post_verify = True
        planner = BootstrapPlanner(gcloud_adapter=adapter, contract=self.contract, clock=self.clock)

        res = planner.authorize("test-proj", "INV-GCP-2026-000001", ttl_hours=8, auto_confirm=True)
        self.assertEqual(res.result, BootstrapStatus.AUTHORIZATION_VERIFICATION_FAILED)


if __name__ == "__main__":
    unittest.main()
