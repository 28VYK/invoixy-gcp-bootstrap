"""Unit tests for authorize mutation flow, API readiness, and single consistent expiry."""

import unittest
from datetime import datetime, timedelta, timezone

from invoixy_bootstrap.contract import load_auditor_contract
from invoixy_bootstrap.gcloud import FakeGcloudAdapter
from invoixy_bootstrap.models import BootstrapStatus
from invoixy_bootstrap.planner import BootstrapPlanner


class TestAuthorize(unittest.TestCase):
    def setUp(self):
        self.contract = load_auditor_contract()
        self.current_time = datetime(2026, 8, 25, 10, 0, 0, tzinfo=timezone.utc)
        self.clock = lambda: self.current_time

    def test_authorize_creates_role_and_binding(self):
        adapter = FakeGcloudAdapter()
        planner = BootstrapPlanner(gcloud_adapter=adapter, contract=self.contract, clock=self.clock)

        res = planner.authorize("test-proj", "INV-GCP-2026-000001", ttl_hours=8, auto_confirm=True)
        self.assertEqual(res.result, BootstrapStatus.AUTHORIZED)
        self.assertEqual(len(res.changes), 2)

        # Verify canonical timestamp
        d = res.to_dict()
        self.assertEqual(d["authorization"]["expires_at_utc"], "2026-08-25T18:00:00Z")

    def test_authorize_single_consistent_expiry_with_advancing_clock(self):
        adapter = FakeGcloudAdapter()
        # Clock advances by 5 seconds on each call
        class AdvancingClock:
            def __init__(self, start_dt):
                self.dt = start_dt
            def __call__(self):
                t = self.dt
                self.dt += timedelta(seconds=5)
                return t

        clock = AdvancingClock(datetime(2026, 8, 25, 10, 0, 0, tzinfo=timezone.utc))
        planner = BootstrapPlanner(gcloud_adapter=adapter, contract=self.contract, clock=clock)

        res = planner.authorize("test-proj", "INV-GCP-2026-000001", ttl_hours=1, auto_confirm=True)
        self.assertEqual(res.result, BootstrapStatus.AUTHORIZED)

        # Check call history condition expression uses initial plan expiry (11:00:00Z)
        add_call = [c for c in adapter.call_history if c[0] == "add_iam_policy_binding"][0]
        self.assertIn("2026-08-25T11:00:00Z", add_call[1]["condition_expression"])

    def test_authorize_fails_closed_when_iam_api_disabled(self):
        adapter = FakeGcloudAdapter(iam_api_enabled=False)
        planner = BootstrapPlanner(gcloud_adapter=adapter, contract=self.contract, clock=self.clock)

        res = planner.authorize("test-proj", "INV-GCP-2026-000001", ttl_hours=8, auto_confirm=True)
        self.assertEqual(res.result, BootstrapStatus.IAM_API_DISABLED)
        self.assertEqual(len(adapter.call_history), 0)  # Zero mutations!

    def test_authorize_fails_closed_when_iam_api_unknown(self):
        adapter = FakeGcloudAdapter(fail_service_check=True)
        planner = BootstrapPlanner(gcloud_adapter=adapter, contract=self.contract, clock=self.clock)

        res = planner.authorize("test-proj", "INV-GCP-2026-000001", ttl_hours=8, auto_confirm=True)
        self.assertEqual(res.result, BootstrapStatus.IAM_API_STATUS_UNKNOWN)
        self.assertEqual(len(adapter.call_history), 0)


if __name__ == "__main__":
    unittest.main()
