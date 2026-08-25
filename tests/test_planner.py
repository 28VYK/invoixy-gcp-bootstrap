"""Unit tests for planner read-only evaluation."""

import unittest
from datetime import datetime, timezone

from invoixy_bootstrap.contract import load_auditor_contract
from invoixy_bootstrap.gcloud import FakeGcloudAdapter
from invoixy_bootstrap.models import BootstrapStatus
from invoixy_bootstrap.planner import BootstrapPlanner


class TestPlanner(unittest.TestCase):
    def setUp(self):
        self.contract = load_auditor_contract()
        self.clock_dt = datetime(2026, 8, 25, 10, 0, 0, tzinfo=timezone.utc)
        self.clock = lambda: self.clock_dt

    def test_plan_proposes_create_role_and_add_binding_when_role_missing(self):
        adapter = FakeGcloudAdapter()
        planner = BootstrapPlanner(gcloud_adapter=adapter, contract=self.contract, clock=self.clock)

        plan = planner.plan(project_id="test-proj", audit_id="INV-GCP-2026-000001", ttl_hours=8)
        self.assertEqual(plan.role_status, BootstrapStatus.ROLE_MISSING)
        self.assertEqual(plan.binding_status, BootstrapStatus.NOT_AUTHORIZED)
        self.assertEqual(plan.proposed_mutations, ["CREATE_ROLE", "ADD_BINDING"])
        self.assertEqual(len(adapter.call_history), 0)  # Pure read-only

    def test_plan_proposes_add_binding_only_when_exact_role_exists(self):
        adapter = FakeGcloudAdapter()
        adapter.create_custom_role(
            "test-proj",
            self.contract.role_id,
            self.contract.title,
            self.contract.description,
            self.contract.stage,
            self.contract.included_permissions,
        )
        adapter.call_history.clear()

        planner = BootstrapPlanner(gcloud_adapter=adapter, contract=self.contract, clock=self.clock)
        plan = planner.plan(project_id="test-proj", audit_id="INV-GCP-2026-000001", ttl_hours=8)

        self.assertEqual(plan.role_status, BootstrapStatus.ROLE_EXACT_MATCH)
        self.assertEqual(plan.proposed_mutations, ["ADD_BINDING"])
        self.assertEqual(len(adapter.call_history), 0)

    def test_plan_blocks_on_role_drift(self):
        adapter = FakeGcloudAdapter()
        adapter.create_custom_role(
            "test-proj",
            self.contract.role_id,
            self.contract.title,
            self.contract.description,
            self.contract.stage,
            ["compute.instances.list"],  # Only 1 perm -> drift
        )
        planner = BootstrapPlanner(gcloud_adapter=adapter, contract=self.contract, clock=self.clock)
        plan = planner.plan(project_id="test-proj", audit_id="INV-GCP-2026-000001")

        self.assertEqual(plan.role_status, BootstrapStatus.ROLE_DRIFT)
        self.assertEqual(plan.overall_status, BootstrapStatus.ROLE_DRIFT)
        self.assertEqual(plan.proposed_mutations, [])


if __name__ == "__main__":
    unittest.main()
