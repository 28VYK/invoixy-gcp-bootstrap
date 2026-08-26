"""Unit tests for the Interactive Terminal Wizard and Non-TTY Safety."""

import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from invoixy_bootstrap.cli import main
from invoixy_bootstrap.gcloud import GcloudAdapter
from invoixy_bootstrap.models import (
    BindingInfo,
    BootstrapStatus,
    ExecutionResult,
    PlanResult,
    ProjectInfo,
    RoleContract,
)
from invoixy_bootstrap.planner import BootstrapPlanner
from invoixy_bootstrap.wizard import run_wizard


class FakeGcloudForWizard(GcloudAdapter):
    """Deterministic fake Gcloud adapter for testing wizard interactions."""

    def __init__(
        self,
        gcloud_installed: bool = True,
        version_str: str = "513.0.0",
        active_account: str = "admin@example.com",
        configured_project: str = "sample-proj",
    ):
        self.gcloud_installed = gcloud_installed
        self.version_str = version_str
        self.active_account = active_account
        self.configured_project = configured_project
        self.custom_roles = {}
        self.bindings = {}
        self.services = {"sample-proj": ["iam.googleapis.com"]}

    def get_version(self):
        if not self.gcloud_installed:
            return False, "gcloud executable not found."
        return True, self.version_str

    def get_active_account(self):
        return self.active_account

    def get_configured_project(self):
        return self.configured_project

    def describe_project(self, project_id: str):
        if project_id.startswith("missing"):
            return BootstrapStatus.PROJECT_NOT_ACCESSIBLE, None
        return BootstrapStatus.ROLE_EXACT_MATCH, ProjectInfo(project_id=project_id)

    def check_service_enabled(self, project_id: str, service_name: str = "iam.googleapis.com"):
        if service_name in self.services.get(project_id, []):
            return BootstrapStatus.AUTHORIZED, True
        return BootstrapStatus.IAM_API_DISABLED, False

    def describe_custom_role(self, project_id: str, role_id: str, expected_fingerprint: str):
        if role_id not in self.custom_roles:
            return BootstrapStatus.ROLE_MISSING, None
        perms = self.custom_roles[role_id]
        if len(perms) == 42:
            return BootstrapStatus.ROLE_EXACT_MATCH, perms
        return BootstrapStatus.ROLE_DRIFT, perms

    def create_custom_role(self, project_id, role_id, title, description, stage, permissions):
        self.custom_roles[role_id] = permissions
        return True, None

    def get_invoixy_bindings(self, project_id, role_id, scanner_member, clock_now=None):
        return BootstrapStatus.ROLE_EXACT_MATCH, self.bindings.get(project_id, [])

    def add_iam_policy_binding(self, project_id, role_id, member, condition_title, condition_expression, condition_description=""):
        b = BindingInfo(
            role=role_id,
            member=member,
            condition_title=condition_title,
            condition_description=condition_description,
            condition_expression=condition_expression,
            is_exact_match=True,
            is_expired=False,
        )
        self.bindings.setdefault(project_id, []).append(b)
        return True, None

    def remove_iam_policy_binding(self, project_id, role_id, member, condition_title, condition_expression, condition_description=""):
        current = self.bindings.get(project_id, [])
        filtered = [b for b in current if b.condition_title != condition_title]
        self.bindings[project_id] = filtered
        return True, None


class TestWizard(unittest.TestCase):
    """Test suite for interactive wizard UX, validation, and CLI entry routing."""

    def setUp(self):
        self.adapter = FakeGcloudForWizard()
        self.planner = BootstrapPlanner(gcloud_adapter=self.adapter)
        self.printed_lines = []

    def _print_capture(self, text: str = ""):
        self.printed_lines.append(str(text))

    def _get_output(self) -> str:
        return "\n".join(self.printed_lines)

    # 1. CLI Routing Tests
    def test_cli_no_args_tty_launches_wizard(self):
        with patch("sys.stdin.isatty", return_value=True), patch("invoixy_bootstrap.wizard.run_wizard", return_value=0) as mock_wizard:
            code = main([])
            self.assertEqual(code, 0)
            mock_wizard.assert_called_once()

    def test_cli_no_args_non_tty_fails_without_prompt(self):
        with patch("sys.stdin.isatty", return_value=False), patch("invoixy_bootstrap.wizard.run_wizard") as mock_wizard:
            code = main([])
            self.assertEqual(code, 1)
            mock_wizard.assert_not_called()

    def test_cli_explicit_plan_bypasses_wizard(self):
        with patch("invoixy_bootstrap.wizard.run_wizard") as mock_wizard, patch("invoixy_bootstrap.cli.BootstrapPlanner") as mock_p_cls:
            mock_p = mock_p_cls.return_value
            mock_p.plan.return_value = PlanResult(
                contract_version=1,
                role_id="InvoixySecurityAuditorV1",
                permission_fingerprint="fp",
                scanner_member="sa",
                audit_id="INV-GCP-2026-000001",
                project_id="sample-proj",
                active_account="acc",
                configured_project="sample-proj",
                project_mismatch=False,
                role_status=BootstrapStatus.ROLE_EXACT_MATCH,
                binding_status=BootstrapStatus.NOT_AUTHORIZED,
                overall_status=BootstrapStatus.ROLE_EXACT_MATCH,
                proposed_expiry_utc=None,
            )
            code = main(["plan", "--project", "sample-proj", "--audit-id", "INV-GCP-2026-000001"])
            self.assertEqual(code, 0)
            mock_wizard.assert_not_called()
            mock_p.plan.assert_called_once()

    def test_cli_explicit_authorize_bypasses_wizard(self):
        with patch("invoixy_bootstrap.wizard.run_wizard") as mock_wizard, patch("invoixy_bootstrap.cli.BootstrapPlanner") as mock_p_cls:
            mock_p = mock_p_cls.return_value
            mock_p.authorize.return_value = ExecutionResult(
                command="authorize",
                result=BootstrapStatus.AUTHORIZED,
                project_id="sample-proj",
                audit_id="INV-GCP-2026-000001",
            )
            code = main(["authorize", "--project", "sample-proj", "--audit-id", "INV-GCP-2026-000001", "--yes"])
            self.assertEqual(code, 0)
            mock_wizard.assert_not_called()
            mock_p.authorize.assert_called_once()

    def test_cli_explicit_status_bypasses_wizard(self):
        with patch("invoixy_bootstrap.wizard.run_wizard") as mock_wizard, patch("invoixy_bootstrap.cli.BootstrapPlanner") as mock_p_cls:
            mock_p = mock_p_cls.return_value
            mock_p.status.return_value = ExecutionResult(
                command="status",
                result=BootstrapStatus.AUTHORIZED,
                project_id="sample-proj",
            )
            code = main(["status", "--project", "sample-proj"])
            self.assertEqual(code, 0)
            mock_wizard.assert_not_called()
            mock_p.status.assert_called_once()

    def test_cli_explicit_revoke_bypasses_wizard(self):
        with patch("invoixy_bootstrap.wizard.run_wizard") as mock_wizard, patch("invoixy_bootstrap.cli.BootstrapPlanner") as mock_p_cls:
            mock_p = mock_p_cls.return_value
            mock_p.revoke.return_value = ExecutionResult(
                command="revoke",
                result=BootstrapStatus.NOT_AUTHORIZED,
                project_id="sample-proj",
                audit_id="INV-GCP-2026-000001",
            )
            code = main(["revoke", "--project", "sample-proj", "--audit-id", "INV-GCP-2026-000001", "--yes"])
            self.assertEqual(code, 0)
            mock_wizard.assert_not_called()
            mock_p.revoke.assert_called_once()

    # 2. Wizard Preflight & Exit Tests
    def test_wizard_exit(self):
        inputs = iter(["4"])
        code = run_wizard(
            planner=self.planner,
            gcloud=self.adapter,
            input_fn=lambda _: next(inputs),
            print_fn=self._print_capture,
        )
        self.assertEqual(code, 0)
        self.assertIn("Exiting.", self._get_output())

    def test_wizard_ctrl_c_safe_exit(self):
        def raise_keyboard_interrupt(_):
            raise KeyboardInterrupt()

        code = run_wizard(
            planner=self.planner,
            gcloud=self.adapter,
            input_fn=raise_keyboard_interrupt,
            print_fn=self._print_capture,
        )
        self.assertEqual(code, 0)
        self.assertIn("Operation cancelled. Exiting.", self._get_output())

    def test_wizard_eof_safe_exit(self):
        def raise_eof(_):
            raise EOFError()

        code = run_wizard(
            planner=self.planner,
            gcloud=self.adapter,
            input_fn=raise_eof,
            print_fn=self._print_capture,
        )
        self.assertEqual(code, 0)
        self.assertIn("Operation cancelled. Exiting.", self._get_output())

    def test_wizard_gcloud_missing(self):
        bad_adapter = FakeGcloudForWizard(gcloud_installed=False)
        code = run_wizard(
            planner=self.planner,
            gcloud=bad_adapter,
            input_fn=lambda _: "4",
            print_fn=self._print_capture,
        )
        self.assertEqual(code, 1)
        self.assertIn("Google Cloud CLI error", self._get_output())
        self.assertIn("https://cloud.google.com/sdk/docs/install", self._get_output())

    def test_wizard_unauthenticated(self):
        bad_adapter = FakeGcloudForWizard(active_account=None)
        code = run_wizard(
            planner=self.planner,
            gcloud=bad_adapter,
            input_fn=lambda _: "4",
            print_fn=self._print_capture,
        )
        self.assertEqual(code, 1)
        self.assertIn("No active Google Cloud CLI account was detected", self._get_output())
        self.assertIn("gcloud auth login", self._get_output())

    # 3. Wizard Authorize Flow Tests
    def test_wizard_authorize_default_ttl_8(self):
        inputs = iter([
            "1",                      # Menu: Authorize
            "sample-proj",            # Project ID
            "INV-GCP-2026-000001",    # Audit ID
            "",                       # Duration (default 8)
            "y",                      # Confirm
            "4",                      # Exit
        ])
        code = run_wizard(
            planner=self.planner,
            gcloud=self.adapter,
            input_fn=lambda _: next(inputs),
            print_fn=self._print_capture,
        )
        self.assertEqual(code, 0)
        out = self._get_output()
        self.assertIn("Access Duration:         8 hours", out)
        self.assertIn("AUTHORIZATION SUCCESSFUL", out)
        self.assertEqual(len(self.adapter.bindings.get("sample-proj", [])), 1)

    def test_wizard_authorize_ttl_24_allowed(self):
        inputs = iter([
            "1",                      # Menu: Authorize
            "sample-proj",            # Project ID
            "INV-GCP-2026-000002",    # Audit ID
            "24",                     # Duration: 24h
            "yes",                    # Confirm
            "4",                      # Exit
        ])
        code = run_wizard(
            planner=self.planner,
            gcloud=self.adapter,
            input_fn=lambda _: next(inputs),
            print_fn=self._print_capture,
        )
        self.assertEqual(code, 0)
        out = self._get_output()
        self.assertIn("Access Duration:         24 hours", out)
        self.assertIn("AUTHORIZATION SUCCESSFUL", out)

    def test_wizard_authorize_ttl_over_24_rejected(self):
        inputs = iter([
            "1",                      # Menu: Authorize
            "sample-proj",            # Project ID
            "INV-GCP-2026-000003",    # Audit ID
            "25",                     # Invalid TTL: 25h
            "4",                      # Exit
        ])
        code = run_wizard(
            planner=self.planner,
            gcloud=self.adapter,
            input_fn=lambda _: next(inputs),
            print_fn=self._print_capture,
        )
        self.assertEqual(code, 0)
        out = self._get_output()
        self.assertIn("Invalid TTL", out)
        self.assertIn("Must be between 1 and 24 hours", out)
        self.assertNotIn("AUTHORIZATION SUCCESSFUL", out)

    def test_wizard_authorize_invalid_audit_id(self):
        inputs = iter([
            "1",                      # Menu: Authorize
            "sample-proj",            # Project ID
            "INVALID_AUDIT_123",      # Invalid Audit ID
            "4",                      # Exit
        ])
        code = run_wizard(
            planner=self.planner,
            gcloud=self.adapter,
            input_fn=lambda _: next(inputs),
            print_fn=self._print_capture,
        )
        self.assertEqual(code, 0)
        out = self._get_output()
        self.assertIn("Invalid Audit ID", out)
        self.assertNotIn("PROPOSED AUTHORIZATION PLAN", out)

    def test_wizard_authorize_cancel_zero_mutation(self):
        inputs = iter([
            "1",                      # Menu: Authorize
            "sample-proj",            # Project ID
            "INV-GCP-2026-000004",    # Audit ID
            "8",                      # Duration: 8
            "n",                      # Cancel!
            "4",                      # Exit
        ])
        code = run_wizard(
            planner=self.planner,
            gcloud=self.adapter,
            input_fn=lambda _: next(inputs),
            print_fn=self._print_capture,
        )
        self.assertEqual(code, 0)
        out = self._get_output()
        self.assertIn("Authorization cancelled. Zero changes made.", out)
        # Ensure zero bindings created
        self.assertNotIn("INV-GCP-2026-000004", [b.condition_title for b in self.adapter.bindings.get("sample-proj", [])])

    def test_wizard_already_authorized_no_renewal(self):
        # First authorize
        self.planner.authorize("sample-proj", "INV-GCP-2026-000005", ttl_hours=8, auto_confirm=True)
        # Now try via wizard
        inputs = iter([
            "1",                      # Menu: Authorize
            "sample-proj",            # Project ID
            "INV-GCP-2026-000005",    # Audit ID
            "8",                      # Duration: 8
            "4",                      # Exit
        ])
        code = run_wizard(
            planner=self.planner,
            gcloud=self.adapter,
            input_fn=lambda _: next(inputs),
            print_fn=self._print_capture,
        )
        self.assertEqual(code, 0)
        out = self._get_output()
        self.assertIn("Notice: Authorization is already active for Audit ID 'INV-GCP-2026-000005'.", out)

    # 4. Wizard Status & Revoke Tests
    def test_wizard_status(self):
        self.planner.authorize("sample-proj", "INV-GCP-2026-000006", ttl_hours=8, auto_confirm=True)
        inputs = iter([
            "2",                      # Menu: Status
            "sample-proj",            # Project ID
            "INV-GCP-2026-000006",    # Audit ID
            "4",                      # Exit
        ])
        code = run_wizard(
            planner=self.planner,
            gcloud=self.adapter,
            input_fn=lambda _: next(inputs),
            print_fn=self._print_capture,
        )
        self.assertEqual(code, 0)
        out = self._get_output()
        self.assertIn("INVOIXY AUTHORIZATION STATUS", out)
        self.assertIn("Status:              AUTHORIZED", out)

    def test_wizard_revoke_cancel_zero_mutation(self):
        self.planner.authorize("sample-proj", "INV-GCP-2026-000007", ttl_hours=8, auto_confirm=True)
        inputs = iter([
            "3",                      # Menu: Revoke
            "sample-proj",            # Project ID
            "INV-GCP-2026-000007",    # Audit ID
            "no",                     # Cancel
            "4",                      # Exit
        ])
        code = run_wizard(
            planner=self.planner,
            gcloud=self.adapter,
            input_fn=lambda _: next(inputs),
            print_fn=self._print_capture,
        )
        self.assertEqual(code, 0)
        out = self._get_output()
        self.assertIn("Revocation cancelled. Zero changes made.", out)
        # Binding still exists
        self.assertEqual(len(self.adapter.bindings.get("sample-proj", [])), 1)

    def test_wizard_revoke_exact_binding_only(self):
        self.planner.authorize("sample-proj", "INV-GCP-2026-000008", ttl_hours=8, auto_confirm=True)
        inputs = iter([
            "3",                      # Menu: Revoke
            "sample-proj",            # Project ID
            "INV-GCP-2026-000008",    # Audit ID
            "yes",                    # Confirm
            "4",                      # Exit
        ])
        code = run_wizard(
            planner=self.planner,
            gcloud=self.adapter,
            input_fn=lambda _: next(inputs),
            print_fn=self._print_capture,
        )
        self.assertEqual(code, 0)
        out = self._get_output()
        self.assertIn("REVOCATION SUCCESSFUL", out)
        self.assertEqual(len(self.adapter.bindings.get("sample-proj", [])), 0)

    # 5. Domain Invariants
    def test_wizard_iam_api_disabled(self):
        self.adapter.services["disabled-proj"] = []
        inputs = iter([
            "1",
            "disabled-proj",
            "INV-GCP-2026-000009",
            "8",
            "4",
        ])
        code = run_wizard(
            planner=self.planner,
            gcloud=self.adapter,
            input_fn=lambda _: next(inputs),
            print_fn=self._print_capture,
        )
        self.assertEqual(code, 0)
        out = self._get_output()
        self.assertIn("'iam.googleapis.com' API is disabled", out)
        self.assertIn("will not auto-enable APIs", out)

    def test_wizard_role_drift(self):
        self.adapter.custom_roles["InvoixySecurityAuditorV1"] = ["compute.instances.get"]  # 1 perm instead of 42
        inputs = iter([
            "1",
            "sample-proj",
            "INV-GCP-2026-000010",
            "8",
            "4",
        ])
        code = run_wizard(
            planner=self.planner,
            gcloud=self.adapter,
            input_fn=lambda _: next(inputs),
            print_fn=self._print_capture,
        )
        self.assertEqual(code, 0)
        out = self._get_output()
        self.assertIn("permissions differ from frozen V1 contract", out)
        self.assertIn("Mutation blocked", out)

    def test_explicit_authorize_yes_remains_noninteractive(self):
        res = self.planner.authorize(
            project_id="sample-proj",
            audit_id="INV-GCP-2026-000011",
            ttl_hours=8,
            auto_confirm=True,
        )
        self.assertEqual(res.result, BootstrapStatus.AUTHORIZED)
        self.assertEqual(len(res.changes), 2)  # role + binding

    def test_explicit_json_output_unchanged(self):
        plan_res = self.planner.plan(
            project_id="sample-proj",
            audit_id="INV-GCP-2026-000012",
            ttl_hours=8,
        )
        d = plan_res.to_dict()
        self.assertEqual(d["command"], "plan")
        self.assertEqual(d["schema_version"], 1)
        self.assertEqual(d["role_id"], "InvoixySecurityAuditorV1")

    def test_explicit_dry_run_unchanged(self):
        plan_res = self.planner.plan(
            project_id="sample-proj",
            audit_id="INV-GCP-2026-000013",
            ttl_hours=8,
        )
        self.assertIn("ADD_BINDING", plan_res.proposed_mutations)
        # Ensure no binding was added to adapter
        self.assertNotIn("INV-GCP-2026-000013", [b.condition_title for b in self.adapter.bindings.get("sample-proj", [])])

