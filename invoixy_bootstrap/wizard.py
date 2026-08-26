"""Interactive Terminal Wizard for Invoixy GCP Bootstrap."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from typing import Callable, Optional

from invoixy_bootstrap.conditions import (
    DEFAULT_TTL_HOURS,
    MAX_TTL_HOURS,
    MIN_TTL_HOURS,
    ValidationError,
    build_condition_title,
    format_canonical_utc_timestamp,
    validate_audit_id,
    validate_project_id,
    validate_ttl_hours,
)
from invoixy_bootstrap.gcloud import GcloudAdapter, RealGcloudAdapter
from invoixy_bootstrap.models import BootstrapStatus, PlanResult
from invoixy_bootstrap.planner import BootstrapPlanner


def _safe_input(prompt: str, input_fn: Callable[[str], str] = input) -> str:
    """Read user input, stripping whitespace."""
    return input_fn(prompt).strip()


def run_wizard(
    planner: Optional[BootstrapPlanner] = None,
    gcloud: Optional[GcloudAdapter] = None,
    input_fn: Callable[[str], str] = input,
    print_fn: Callable[[str], None] = print,
) -> int:
    """
    Run the interactive terminal wizard.
    Reuses existing BootstrapPlanner and GcloudAdapter implementations directly.
    """
    gcloud_adapter = gcloud or RealGcloudAdapter()
    planner_engine = planner or BootstrapPlanner(gcloud_adapter=gcloud_adapter)

    print_fn("============================================================")
    print_fn("Invoixy Google Cloud Security Review")
    print_fn("Temporary Google Cloud authorization assistant")
    print_fn("============================================================")

    # 1. Gcloud Preflight
    ver_ok, ver_msg = gcloud_adapter.get_version()
    if not ver_ok:
        print_fn(f"Google Cloud CLI error: {ver_msg}")
        print_fn("Prerequisite: Please install Google Cloud SDK (https://cloud.google.com/sdk/docs/install).")
        return 1

    active_account = gcloud_adapter.get_active_account()
    if not active_account:
        print_fn(f"Google Cloud CLI: detected ({ver_msg})")
        print_fn("No active Google Cloud CLI account was detected.")
        print_fn("Run 'gcloud auth login' separately, then run this tool again.")
        return 1

    print_fn(f"Google Cloud CLI: detected ({ver_msg})")
    print_fn(f"Active account:   {active_account}")

    while True:
        print_fn("")
        print_fn("Select an action:")
        print_fn("  1. Authorize a security review")
        print_fn("  2. Check authorization status")
        print_fn("  3. Revoke authorization")
        print_fn("  4. Exit")

        try:
            choice = _safe_input("\nSelect an option [1-4]: ", input_fn=input_fn)
        except (KeyboardInterrupt, EOFError):
            print_fn("\nOperation cancelled. Exiting.")
            return 0

        if choice == "1":
            _flow_authorize(planner_engine, input_fn=input_fn, print_fn=print_fn)
        elif choice == "2":
            _flow_status(planner_engine, input_fn=input_fn, print_fn=print_fn)
        elif choice == "3":
            _flow_revoke(planner_engine, input_fn=input_fn, print_fn=print_fn)
        elif choice == "4" or choice.lower() in {"exit", "quit", "q"}:
            print_fn("Exiting.")
            return 0
        else:
            print_fn(f"Invalid choice '{choice}'. Please select 1, 2, 3, or 4.")


def _flow_authorize(
    planner: BootstrapPlanner,
    input_fn: Callable[[str], str],
    print_fn: Callable[[str], None],
) -> None:
    print_fn("")
    print_fn("--- 1. Authorize Security Review ---")
    try:
        project_id = _safe_input("Google Cloud Project ID: ", input_fn=input_fn)
        if not project_id:
            print_fn("Project ID is required.")
            return
        validate_project_id(project_id)
    except ValidationError as e:
        print_fn(f"Invalid Project ID: {e}")
        return
    except (KeyboardInterrupt, EOFError):
        print_fn("\nOperation cancelled.")
        return

    try:
        audit_id = _safe_input("Invoixy Audit ID (e.g. INV-GCP-2026-000001): ", input_fn=input_fn)
        if not audit_id:
            print_fn("Audit ID is required.")
            return
        validate_audit_id(audit_id)
    except ValidationError as e:
        print_fn(f"Invalid Audit ID: {e}")
        return
    except (KeyboardInterrupt, EOFError):
        print_fn("\nOperation cancelled.")
        return

    try:
        ttl_raw = _safe_input(f"Access duration in hours [{DEFAULT_TTL_HOURS}]: ", input_fn=input_fn)
        ttl_hours = int(ttl_raw) if ttl_raw else DEFAULT_TTL_HOURS
        validate_ttl_hours(ttl_hours)
    except (ValueError, ValidationError) as e:
        print_fn(f"Invalid TTL: {e} (Must be between {MIN_TTL_HOURS} and {MAX_TTL_HOURS} hours).")
        return
    except (KeyboardInterrupt, EOFError):
        print_fn("\nOperation cancelled.")
        return

    print_fn("")
    print_fn("Evaluating authorization plan...")
    plan_res = planner.plan(project_id=project_id, audit_id=audit_id, ttl_hours=ttl_hours)

    if plan_res.overall_status == BootstrapStatus.ALREADY_AUTHORIZED:
        print_fn("")
        print_fn(f"Notice: Authorization is already active for Audit ID '{audit_id}'.")
        if plan_res.proposed_expiry_utc:
            print_fn(f"Current active expiration: {format_canonical_utc_timestamp(plan_res.proposed_expiry_utc)}")
        return

    if plan_res.overall_status == BootstrapStatus.IAM_API_DISABLED:
        print_fn("")
        print_fn(f"Error: 'iam.googleapis.com' API is disabled on project '{project_id}'.")
        print_fn("Invoixy bootstrap will not auto-enable APIs. Please enable the API separately if intended.")
        return

    if plan_res.overall_status == BootstrapStatus.ROLE_DRIFT:
        print_fn("")
        print_fn(f"Error: Custom role '{plan_res.role_id}' exists but permissions differ from frozen V1 contract.")
        print_fn("Mutation blocked to protect IAM integrity.")
        return

    if plan_res.overall_status == BootstrapStatus.PROJECT_NOT_ACCESSIBLE:
        print_fn("")
        print_fn(f"Error: Project '{project_id}' is inaccessible or does not exist.")
        return

    if plan_res.overall_status == BootstrapStatus.CONTRACT_INVALID:
        print_fn("")
        print_fn("Error: Local role contract failed cryptographic verification.")
        return

    # Present concise human plan
    print_fn("")
    print_fn("============================================================")
    print_fn("PROPOSED AUTHORIZATION PLAN")
    print_fn("============================================================")
    print_fn(f"Target Project:          {plan_res.project_id}")
    print_fn(f"Audit Engagement ID:     {plan_res.audit_id}")
    print_fn(f"Custom Role ID:          {plan_res.role_id} (42 permissions)")
    print_fn(f"Role Action:             {'Create new custom role' if 'CREATE_ROLE' in plan_res.proposed_mutations else 'Reuse existing custom role'}")
    print_fn(f"Scanner Identity:        {plan_res.scanner_member}")
    print_fn(f"Access Duration:         {ttl_hours} hours")
    print_fn(f"Calculated Expiry (UTC): {format_canonical_utc_timestamp(plan_res.proposed_expiry_utc) if plan_res.proposed_expiry_utc else 'N/A'}")
    print_fn("------------------------------------------------------------")
    print_fn("What this will do:")
    print_fn("  - Create or reuse the exact InvoixySecurityAuditorV1 role.")
    print_fn("  - Add one temporary conditional IAM binding for the Invoixy scanner.")
    print_fn("")
    print_fn("What this will NOT do:")
    print_fn("  - Enable Google Cloud APIs.")
    print_fn("  - Create service-account keys.")
    print_fn("  - Grant Owner or Editor.")
    print_fn("  - Modify workloads or stored application data.")
    print_fn("  - Create resources in the project.")
    print_fn("============================================================")

    try:
        ans = _safe_input("\nContinue with authorization? [y/N]: ", input_fn=input_fn)
    except (KeyboardInterrupt, EOFError):
        print_fn("\nOperation cancelled. Zero changes made.")
        return

    if ans.lower() not in {"y", "yes"}:
        print_fn("Authorization cancelled. Zero changes made.")
        return

    print_fn("")
    print_fn("Applying authorization...")
    exec_res = planner.authorize(
        project_id=project_id,
        audit_id=audit_id,
        ttl_hours=ttl_hours,
        auto_confirm=True,
    )

    if exec_res.result == BootstrapStatus.AUTHORIZED:
        print_fn("")
        print_fn(">>> AUTHORIZATION SUCCESSFUL <<<")
        for c in exec_res.changes:
            print_fn(f"  [+] {c}")
    else:
        print_fn("")
        print_fn(f">>> AUTHORIZATION FAILED: {exec_res.result.value} <<<")
        for d in exec_res.diagnostics:
            print_fn(f"  - {d}")


def _flow_status(
    planner: BootstrapPlanner,
    input_fn: Callable[[str], str],
    print_fn: Callable[[str], None],
) -> None:
    print_fn("")
    print_fn("--- 2. Check Authorization Status ---")
    try:
        project_id = _safe_input("Google Cloud Project ID: ", input_fn=input_fn)
        if not project_id:
            print_fn("Project ID is required.")
            return
        validate_project_id(project_id)
    except ValidationError as e:
        print_fn(f"Invalid Project ID: {e}")
        return
    except (KeyboardInterrupt, EOFError):
        print_fn("\nOperation cancelled.")
        return

    try:
        audit_id = _safe_input("Invoixy Audit ID (optional, press Enter to inspect all): ", input_fn=input_fn)
        if audit_id:
            validate_audit_id(audit_id)
        else:
            audit_id = None
    except ValidationError as e:
        print_fn(f"Invalid Audit ID: {e}")
        return
    except (KeyboardInterrupt, EOFError):
        print_fn("\nOperation cancelled.")
        return

    print_fn("")
    print_fn("Fetching status...")
    res = planner.status(project_id=project_id, audit_id=audit_id)

    print_fn("")
    print_fn("============================================================")
    print_fn("INVOIXY AUTHORIZATION STATUS")
    print_fn("============================================================")
    print_fn(f"Target Project:      {res.project_id}")
    print_fn(f"Audit ID:            {res.audit_id or 'All'}")
    print_fn(f"Status:              {res.result.value}")
    if res.role_info:
        print_fn(f"Role:                {res.role_info.get('id')} ({res.role_info.get('status')})")
    if res.authorization:
        print_fn(f"Condition Title:     {res.authorization.get('condition_title')}")
        print_fn(f"Expires At (UTC):    {res.authorization.get('expires_at_utc')}")
        print_fn(f"Is Expired:          {res.authorization.get('is_expired')}")
    if res.diagnostics:
        print_fn("Details:")
        for d in res.diagnostics:
            print_fn(f"  - {d}")
    print_fn("============================================================")


def _flow_revoke(
    planner: BootstrapPlanner,
    input_fn: Callable[[str], str],
    print_fn: Callable[[str], None],
) -> None:
    print_fn("")
    print_fn("--- 3. Revoke Authorization ---")
    try:
        project_id = _safe_input("Google Cloud Project ID: ", input_fn=input_fn)
        if not project_id:
            print_fn("Project ID is required.")
            return
        validate_project_id(project_id)
    except ValidationError as e:
        print_fn(f"Invalid Project ID: {e}")
        return
    except (KeyboardInterrupt, EOFError):
        print_fn("\nOperation cancelled.")
        return

    try:
        audit_id = _safe_input("Invoixy Audit ID to revoke: ", input_fn=input_fn)
        if not audit_id:
            print_fn("Audit ID is required.")
            return
        validate_audit_id(audit_id)
    except ValidationError as e:
        print_fn(f"Invalid Audit ID: {e}")
        return
    except (KeyboardInterrupt, EOFError):
        print_fn("\nOperation cancelled.")
        return

    print_fn("")
    print_fn("Inspecting authorization status...")
    status_res = planner.status(project_id=project_id, audit_id=audit_id)

    if status_res.result == BootstrapStatus.NOT_AUTHORIZED:
        print_fn("")
        print_fn(f"Target Project:       {project_id}")
        print_fn(f"Audit ID:             {audit_id}")
        print_fn(f"Status:               {status_res.result.value}")
        print_fn("Notice: No active or expired binding found for this Audit ID. Nothing to revoke.")
        return

    if status_res.result not in {BootstrapStatus.AUTHORIZED, BootstrapStatus.EXPIRED_BINDING_PRESENT}:
        print_fn("")
        print_fn(f"Target Project:       {project_id}")
        print_fn(f"Audit ID:             {audit_id}")
        print_fn(f"Status:               {status_res.result.value}")
        if status_res.diagnostics:
            print_fn("Details:")
            for d in status_res.diagnostics:
                print_fn(f"  - {d}")
        print_fn("Revocation blocked. Zero changes made.")
        return

    auth = status_res.authorization or {}
    cond_title = auth.get("condition_title") or build_condition_title(audit_id)
    expires_at = auth.get("expires_at_utc") or "N/A"
    is_expired = auth.get("is_expired")
    expired_str = "Yes" if is_expired else "No"

    print_fn("")
    print_fn("============================================================")
    print_fn("AUTHORIZATION IDENTIFIED FOR REVOCATION")
    print_fn("============================================================")
    print_fn(f"Target Project:       {project_id}")
    print_fn(f"Audit ID:             {audit_id}")
    print_fn(f"Status:               {status_res.result.value}")
    print_fn(f"Condition Title:      {cond_title}")
    print_fn(f"Expiration (UTC):     {expires_at}")
    print_fn(f"Is Expired:           {expired_str}")
    print_fn("------------------------------------------------------------")
    print_fn(f"Condition to remove:  {cond_title}")
    print_fn("Custom role remains in project (InvoixySecurityAuditorV1).")
    print_fn("============================================================")

    try:
        ans = _safe_input("\nRevoke this authorization? [y/N]: ", input_fn=input_fn)
    except (KeyboardInterrupt, EOFError):
        print_fn("\nOperation cancelled. Zero changes made.")
        return

    if ans.lower() not in {"y", "yes"}:
        print_fn("Revocation cancelled. Zero changes made.")
        return

    print_fn("")
    print_fn("Revoking authorization...")
    exec_res = planner.revoke(
        project_id=project_id,
        audit_id=audit_id,
        auto_confirm=True,
    )

    if exec_res.result == BootstrapStatus.NOT_AUTHORIZED:
        print_fn("")
        print_fn(">>> REVOCATION SUCCESSFUL <<<")
        for c in exec_res.changes:
            print_fn(f"  [-] {c}")
    else:
        print_fn("")
        print_fn(f">>> REVOCATION FAILED: {exec_res.result.value} <<<")
        for d in exec_res.diagnostics:
            print_fn(f"  - {d}")

