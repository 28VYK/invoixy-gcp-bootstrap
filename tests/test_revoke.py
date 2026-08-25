"""Unit tests for surgical revoke operations."""

import unittest
from datetime import datetime, timezone

from invoixy_bootstrap.contract import load_auditor_contract
from invoixy_bootstrap.gcloud import FakeGcloudAdapter
from invoixy_bootstrap.models import BootstrapStatus
from invoixy_bootstrap.planner import BootstrapPlanner


class TestRevoke(unittest.TestCase):
    def setUp(self):
        self.contract = load_auditor_contract()
        self.clock_dt = datetime(2026, 8, 25, 10, 0, 0, tzinfo=timezone.utc)
        self.clock = lambda: self.clock_dt

    def test_revoke_removes_exact_binding_and_preserves_role(self):
        adapter = FakeGcloudAdapter()
        planner = BootstrapPlanner(gcloud_adapter=adapter, contract=self.contract, clock=self.clock)

        # Authorize first
        planner.authorize("test-proj", "INV-GCP-2026-000001", ttl_hours=8, auto_confirm=True)

        # Revoke
        res = planner.revoke("test-proj", "INV-GCP-2026-000001", auto_confirm=True)
        self.assertEqual(res.result, BootstrapStatus.NOT_AUTHORIZED)

        # Role remains intact
        role_st, _ = adapter.describe_custom_role("test-proj", self.contract.role_id, self.contract.permission_fingerprint)
        self.assertEqual(role_st, BootstrapStatus.ROLE_EXACT_MATCH)

    def test_revoke_preserves_other_audit_id_bindings(self):
        adapter = FakeGcloudAdapter()
        planner = BootstrapPlanner(gcloud_adapter=adapter, contract=self.contract, clock=self.clock)

        planner.authorize("test-proj", "INV-GCP-2026-000001", ttl_hours=8, auto_confirm=True)
        planner.authorize("test-proj", "INV-GCP-2026-000002", ttl_hours=8, auto_confirm=True)

        # Revoke only 000001
        res = planner.revoke("test-proj", "INV-GCP-2026-000001", auto_confirm=True)
        self.assertEqual(res.result, BootstrapStatus.NOT_AUTHORIZED)

        # Status of 000002 is still AUTHORIZED
        st2 = planner.status("test-proj", "INV-GCP-2026-000002")
        self.assertEqual(st2.result, BootstrapStatus.AUTHORIZED)

    def test_revoke_idempotent_when_already_absent(self):
        adapter = FakeGcloudAdapter()
        planner = BootstrapPlanner(gcloud_adapter=adapter, contract=self.contract, clock=self.clock)

        res = planner.revoke("test-proj", "INV-GCP-2026-000001", auto_confirm=True)
        self.assertEqual(res.result, BootstrapStatus.NOT_AUTHORIZED)


if __name__ == "__main__":
    unittest.main()
