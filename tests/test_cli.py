"""Unit tests for CLI parsing and dispatch."""

import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from invoixy_bootstrap.cli import main
from invoixy_bootstrap.contract import load_auditor_contract
from invoixy_bootstrap.gcloud import FakeGcloudAdapter


class TestCli(unittest.TestCase):
    def test_cli_plan_json(self):
        adapter = FakeGcloudAdapter()
        with patch("invoixy_bootstrap.cli.BootstrapPlanner") as mock_planner_cls:
            from invoixy_bootstrap.planner import BootstrapPlanner
            real_p = BootstrapPlanner(gcloud_adapter=adapter, contract=load_auditor_contract())
            mock_planner_cls.return_value = real_p

            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["plan", "--project", "test-proj", "--audit-id", "INV-GCP-2026-000001", "--json"])

            self.assertEqual(code, 0)
            data = json.loads(buf.getvalue())
            self.assertEqual(data["command"], "plan")
            self.assertEqual(data["project_id"], "test-proj")
            self.assertEqual(data["audit_id"], "INV-GCP-2026-000001")


if __name__ == "__main__":
    unittest.main()
