"""Command-Line Interface for Invoixy GCP Bootstrap."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from invoixy_bootstrap.conditions import DEFAULT_TTL_HOURS
from invoixy_bootstrap.models import BootstrapStatus, PlanResult
from invoixy_bootstrap.planner import BootstrapPlanner


def _print_plan_human(plan: PlanResult) -> None:
    print("\n============================================================")
    print("INVOIXY GCP SECURITY REVIEW — AUTHORIZATION PLAN")
    print("============================================================")
    print(f"Target Project:          {plan.project_id}")
    print(f"Audit Engagement ID:     {plan.audit_id}")
    print(f"Active gcloud Account:   {plan.active_account or 'Unknown'}")
    if plan.project_mismatch:
        print(f"Configured gcloud Proj:  {plan.configured_project} (MISMATCH)")
    print(f"Custom Role ID:          {plan.role_id}")
    print(f"Role Fingerprint:        {plan.permission_fingerprint}")
    print(f"Scanner Service Account: {plan.scanner_member}")
    print(f"Proposed Expiration:     {plan.proposed_expiry_utc.isoformat() if plan.proposed_expiry_utc else 'N/A'}")
    print("------------------------------------------------------------")
    print(f"Role Status:             {plan.role_status.value}")
    print(f"Binding Status:          {plan.binding_status.value}")
    print(f"Overall State:           {plan.overall_status.value}")
    print("------------------------------------------------------------")
    print("Proposed Mutations:")
    if plan.proposed_mutations:
        for m in plan.proposed_mutations:
            print(f"  [+] {m}")
    else:
        print("  (None - no changes required or mutation blocked)")
    print("------------------------------------------------------------")
    if plan.diagnostics:
        print("Diagnostics:")
        for d in plan.diagnostics:
            print(f"  - {d}")
    print("============================================================\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="invoixy-gcp-bootstrap",
        description="Client-side ephemeral IAM permission manager for Invoixy Google Cloud Security Review.",
    )
    subparsers = parser.add_subparsers(dest="command", required=False)

    # 1. PLAN
    p_plan = subparsers.add_parser("plan", help="Evaluate read-only authorization plan.")
    p_plan.add_argument("--project", required=True, help="Target Google Cloud Project ID.")
    p_plan.add_argument("--audit-id", required=True, help="Canonical Audit ID (e.g. INV-GCP-2026-000001).")
    p_plan.add_argument("--ttl-hours", type=int, default=DEFAULT_TTL_HOURS, help="Authorization duration in hours (1-24).")
    p_plan.add_argument("--json", action="store_true", help="Output machine-readable JSON.")

    # 2. AUTHORIZE
    p_auth = subparsers.add_parser("authorize", help="Plan and execute ephemeral IAM authorization.")
    p_auth.add_argument("--project", required=True, help="Target Google Cloud Project ID.")
    p_auth.add_argument("--audit-id", required=True, help="Canonical Audit ID (e.g. INV-GCP-2026-000001).")
    p_auth.add_argument("--ttl-hours", type=int, default=DEFAULT_TTL_HOURS, help="Authorization duration in hours (1-24).")
    p_auth.add_argument("--yes", action="store_true", help="Automatically confirm and apply changes.")
    p_auth.add_argument("--dry-run", action="store_true", help="Execute read-only plan only.")
    p_auth.add_argument("--json", action="store_true", help="Output machine-readable JSON.")

    # 3. STATUS
    p_stat = subparsers.add_parser("status", help="Inspect active or expired Invoixy authorization status.")
    p_stat.add_argument("--project", required=True, help="Target Google Cloud Project ID.")
    p_stat.add_argument("--audit-id", required=False, default=None, help="Optional specific Audit ID.")
    p_stat.add_argument("--json", action="store_true", help="Output machine-readable JSON.")

    # 4. REVOKE
    p_rev = subparsers.add_parser("revoke", help="Revoke Invoixy conditional IAM policy binding.")
    p_rev.add_argument("--project", required=True, help="Target Google Cloud Project ID.")
    p_rev.add_argument("--audit-id", required=True, help="Canonical Audit ID to revoke.")
    p_rev.add_argument("--yes", action="store_true", help="Automatically confirm and apply revocation.")
    p_rev.add_argument("--json", action="store_true", help="Output machine-readable JSON.")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        if sys.stdin.isatty():
            from invoixy_bootstrap.wizard import run_wizard
            return run_wizard()
        else:
            parser.print_help(sys.stderr)
            print("\nError: interactive wizard requires an interactive TTY. Use explicit subcommands in scripts or automation.", file=sys.stderr)
            return 1

    planner = BootstrapPlanner()

    try:
        if args.command == "plan" or (args.command == "authorize" and getattr(args, "dry-run", False)):
            plan_res = planner.plan(
                project_id=args.project,
                audit_id=args.audit_id,
                ttl_hours=args.ttl_hours,
            )
            if args.json:
                print(json.dumps(plan_res.to_dict(), indent=2))
            else:
                _print_plan_human(plan_res)
            return 0 if plan_res.overall_status in {BootstrapStatus.ROLE_EXACT_MATCH, BootstrapStatus.NOT_AUTHORIZED, BootstrapStatus.ALREADY_AUTHORIZED} else 1

        elif args.command == "status":
            res = planner.status(
                project_id=args.project,
                audit_id=args.audit_id,
            )
            if args.json:
                print(json.dumps(res.to_dict(), indent=2))
            else:
                print(f"Status: {res.result.value}")
                for d in res.diagnostics:
                    print(f"  - {d}")
            return 0 if res.result in {BootstrapStatus.AUTHORIZED, BootstrapStatus.NOT_AUTHORIZED} else 1

        elif args.command == "authorize":
            def confirm_cb(p: PlanResult) -> bool:
                _print_plan_human(p)
                print(f"WARNING: This command will modify IAM on project '{p.project_id}'.")
                try:
                    ans = input("Do you wish to proceed with authorization? [y/N]: ").strip().lower()
                    return ans in {"y", "yes"}
                except EOFError:
                    return False

            res = planner.authorize(
                project_id=args.project,
                audit_id=args.audit_id,
                ttl_hours=args.ttl_hours,
                auto_confirm=args.yes,
                confirm_callback=confirm_cb,
            )
            if args.json:
                print(json.dumps(res.to_dict(), indent=2))
            else:
                print(f"\nResult: {res.result.value}")
                for c in res.changes:
                    print(f"  [+] {c}")
                for d in res.diagnostics:
                    print(f"  - {d}")
            return 0 if res.result == BootstrapStatus.AUTHORIZED else 1

        elif args.command == "revoke":
            def confirm_rev(prompt_str: str) -> bool:
                print(f"WARNING: {prompt_str}")
                try:
                    ans = input("Do you wish to proceed with revocation? [y/N]: ").strip().lower()
                    return ans in {"y", "yes"}
                except EOFError:
                    return False

            res = planner.revoke(
                project_id=args.project,
                audit_id=args.audit_id,
                auto_confirm=args.yes,
                confirm_callback=confirm_rev,
            )
            if args.json:
                print(json.dumps(res.to_dict(), indent=2))
            else:
                print(f"\nResult: {res.result.value}")
                for c in res.changes:
                    print(f"  [-] {c}")
                for d in res.diagnostics:
                    print(f"  - {d}")
            return 0 if res.result == BootstrapStatus.NOT_AUTHORIZED else 1

    except Exception as e:
        if getattr(args, "json", False):
            print(json.dumps({"schema_version": 1, "result": "ERROR", "error": str(e)}, indent=2))
        else:
            print(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
