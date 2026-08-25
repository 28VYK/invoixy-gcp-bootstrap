"""Core Lifecycle Planner and Execution Orchestrator."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable, List, Optional, Tuple

from invoixy_bootstrap.conditions import (
    DEFAULT_TTL_HOURS,
    build_condition_description,
    build_condition_expression,
    build_condition_title,
    validate_audit_id,
    validate_project_id,
    validate_ttl_hours,
)
from invoixy_bootstrap.contract import (
    ContractInvalidError,
    load_auditor_contract,
)
from invoixy_bootstrap.gcloud import GcloudAdapter, RealGcloudAdapter
from invoixy_bootstrap.models import (
    BindingInfo,
    BootstrapStatus,
    ExecutionResult,
    PlanResult,
    RoleContract,
)


class BootstrapPlanner:
    """Evaluates and executes IAM authorization lifecycle operations."""

    def __init__(
        self,
        gcloud_adapter: Optional[GcloudAdapter] = None,
        contract: Optional[RoleContract] = None,
        clock: Optional[Callable[[], datetime]] = None,
    ):
        self.gcloud = gcloud_adapter or RealGcloudAdapter()
        self.contract = contract
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _get_contract(self) -> Tuple[Optional[RoleContract], Optional[str]]:
        if self.contract:
            return self.contract, None
        try:
            c = load_auditor_contract()
            return c, None
        except ContractInvalidError as e:
            return None, str(e)
        except Exception as e:
            return None, f"Failed to load contract: {e}"

    def plan(
        self,
        project_id: str,
        audit_id: str,
        ttl_hours: int = DEFAULT_TTL_HOURS,
    ) -> PlanResult:
        """Perform a 100% read-only plan evaluation."""
        validate_project_id(project_id)
        validate_audit_id(audit_id)
        ttl = validate_ttl_hours(ttl_hours)

        contract, contract_err = self._get_contract()
        if not contract:
            return PlanResult(
                contract_version=1,
                role_id="InvoixySecurityAuditorV1",
                permission_fingerprint="unknown",
                scanner_member="unknown",
                audit_id=audit_id,
                project_id=project_id,
                active_account=None,
                configured_project=None,
                project_mismatch=False,
                role_status=BootstrapStatus.CONTRACT_INVALID,
                binding_status=BootstrapStatus.CONTRACT_INVALID,
                overall_status=BootstrapStatus.CONTRACT_INVALID,
                proposed_expiry_utc=None,
                proposed_mutations=[],
                diagnostics=[f"Contract verification failed: {contract_err}"],
            )

        now = self.clock()
        expiry_utc = now + timedelta(hours=ttl)

        # 1. Inspect Gcloud Version & Environment
        ver_ok, ver_msg = self.gcloud.get_version()
        if not ver_ok:
            status = BootstrapStatus.GCLOUD_NOT_FOUND if "not found" in ver_msg.lower() else BootstrapStatus.GCLOUD_TOO_OLD
            return PlanResult(
                contract_version=contract.contract_version,
                role_id=contract.role_id,
                permission_fingerprint=contract.permission_fingerprint,
                scanner_member=contract.scanner_member,
                audit_id=audit_id,
                project_id=project_id,
                active_account=None,
                configured_project=None,
                project_mismatch=False,
                role_status=status,
                binding_status=status,
                overall_status=status,
                proposed_expiry_utc=expiry_utc,
                proposed_mutations=[],
                diagnostics=[ver_msg],
            )

        active_account = self.gcloud.get_active_account()
        configured_proj = self.gcloud.get_configured_project()
        proj_mismatch = (configured_proj is not None and configured_proj != project_id)

        # 2. Inspect Target Project
        proj_status, proj_info = self.gcloud.describe_project(project_id)
        if proj_status != BootstrapStatus.ROLE_EXACT_MATCH:
            return PlanResult(
                contract_version=contract.contract_version,
                role_id=contract.role_id,
                permission_fingerprint=contract.permission_fingerprint,
                scanner_member=contract.scanner_member,
                audit_id=audit_id,
                project_id=project_id,
                active_account=active_account,
                configured_project=configured_proj,
                project_mismatch=proj_mismatch,
                role_status=proj_status,
                binding_status=proj_status,
                overall_status=proj_status,
                proposed_expiry_utc=expiry_utc,
                proposed_mutations=[],
                diagnostics=[f"Project '{project_id}' is not accessible or not active (status: {proj_status.value})."],
            )

        # 3. Inspect Custom Role
        role_status, role_perms = self.gcloud.describe_custom_role(
            project_id=project_id,
            role_id=contract.role_id,
            expected_fingerprint=contract.permission_fingerprint,
        )

        # 4. Inspect IAM Policy & Bindings
        b_status, bindings = self.gcloud.get_invoixy_bindings(
            project_id=project_id,
            role_id=contract.role_id,
            scanner_member=contract.scanner_member,
            clock_now=now,
        )

        expected_cond_title = build_condition_title(audit_id)
        audit_bindings = [b for b in bindings if b.condition_title == expected_cond_title]

        proposed_mutations: List[str] = []
        diagnostics: List[str] = []

        # Role evaluation
        if role_status == BootstrapStatus.ROLE_MISSING:
            proposed_mutations.append("CREATE_ROLE")
            diagnostics.append(f"Custom role '{contract.role_id}' does not exist; will be created with {contract.permission_count} permissions.")
        elif role_status == BootstrapStatus.ROLE_EXACT_MATCH:
            diagnostics.append(f"Custom role '{contract.role_id}' exists with exact matching 42 permissions; will be reused.")
        elif role_status == BootstrapStatus.ROLE_DRIFT:
            diagnostics.append(f"Custom role '{contract.role_id}' exists but permissions differ from frozen V1 contract. Mutation blocked.")
            return PlanResult(
                contract_version=contract.contract_version,
                role_id=contract.role_id,
                permission_fingerprint=contract.permission_fingerprint,
                scanner_member=contract.scanner_member,
                audit_id=audit_id,
                project_id=project_id,
                active_account=active_account,
                configured_project=configured_proj,
                project_mismatch=proj_mismatch,
                role_status=BootstrapStatus.ROLE_DRIFT,
                binding_status=b_status,
                overall_status=BootstrapStatus.ROLE_DRIFT,
                proposed_expiry_utc=expiry_utc,
                proposed_mutations=[],
                diagnostics=diagnostics,
            )
        elif role_status == BootstrapStatus.ROLE_DISABLED:
            diagnostics.append(f"Custom role '{contract.role_id}' is deleted or disabled in project. Mutation blocked.")
            return PlanResult(
                contract_version=contract.contract_version,
                role_id=contract.role_id,
                permission_fingerprint=contract.permission_fingerprint,
                scanner_member=contract.scanner_member,
                audit_id=audit_id,
                project_id=project_id,
                active_account=active_account,
                configured_project=configured_proj,
                project_mismatch=proj_mismatch,
                role_status=BootstrapStatus.ROLE_DISABLED,
                binding_status=b_status,
                overall_status=BootstrapStatus.ROLE_DISABLED,
                proposed_expiry_utc=expiry_utc,
                proposed_mutations=[],
                diagnostics=diagnostics,
            )

        # Binding evaluation
        if len(audit_bindings) == 0:
            proposed_mutations.append("ADD_BINDING")
            diagnostics.append(f"No existing binding for '{expected_cond_title}'; will create conditional binding expiring at {expiry_utc.isoformat()}.")
            overall = BootstrapStatus.NOT_AUTHORIZED
        elif len(audit_bindings) == 1:
            eb = audit_bindings[0]
            if not eb.is_exact_match:
                diagnostics.append(f"Binding for '{expected_cond_title}' exists but has non-canonical role or expression. BINDING_DRIFT.")
                return PlanResult(
                    contract_version=contract.contract_version,
                    role_id=contract.role_id,
                    permission_fingerprint=contract.permission_fingerprint,
                    scanner_member=contract.scanner_member,
                    audit_id=audit_id,
                    project_id=project_id,
                    active_account=active_account,
                    configured_project=configured_proj,
                    project_mismatch=proj_mismatch,
                    role_status=role_status,
                    binding_status=BootstrapStatus.BINDING_DRIFT,
                    overall_status=BootstrapStatus.BINDING_DRIFT,
                    proposed_expiry_utc=expiry_utc,
                    proposed_mutations=[],
                    diagnostics=diagnostics,
                )
            if eb.is_expired:
                proposed_mutations.append("ADD_BINDING")
                diagnostics.append(f"Binding for '{expected_cond_title}' exists but is EXPIRED (expired at {eb.expires_at_utc.isoformat() if eb.expires_at_utc else 'unknown'}). Will re-authorize.")
                overall = BootstrapStatus.EXPIRED_BINDING_PRESENT
            else:
                diagnostics.append(f"Binding for '{expected_cond_title}' is already active and valid until {eb.expires_at_utc.isoformat() if eb.expires_at_utc else 'unknown'}. No mutation needed.")
                overall = BootstrapStatus.ALREADY_AUTHORIZED
        else:
            diagnostics.append(f"Multiple ({len(audit_bindings)}) bindings found matching '{expected_cond_title}'. Ambiguous state.")
            return PlanResult(
                contract_version=contract.contract_version,
                role_id=contract.role_id,
                permission_fingerprint=contract.permission_fingerprint,
                scanner_member=contract.scanner_member,
                audit_id=audit_id,
                project_id=project_id,
                active_account=active_account,
                configured_project=configured_proj,
                project_mismatch=proj_mismatch,
                role_status=role_status,
                binding_status=BootstrapStatus.MULTIPLE_BINDINGS,
                overall_status=BootstrapStatus.MULTIPLE_BINDINGS,
                proposed_expiry_utc=expiry_utc,
                proposed_mutations=[],
                diagnostics=diagnostics,
            )

        return PlanResult(
            contract_version=contract.contract_version,
            role_id=contract.role_id,
            permission_fingerprint=contract.permission_fingerprint,
            scanner_member=contract.scanner_member,
            audit_id=audit_id,
            project_id=project_id,
            active_account=active_account,
            configured_project=configured_proj,
            project_mismatch=proj_mismatch,
            role_status=role_status,
            binding_status=b_status,
            overall_status=overall,
            proposed_expiry_utc=expiry_utc,
            proposed_mutations=proposed_mutations,
            diagnostics=diagnostics,
        )

    def status(
        self,
        project_id: str,
        audit_id: Optional[str] = None,
    ) -> ExecutionResult:
        """Perform a 100% read-only status inspection."""
        validate_project_id(project_id)
        if audit_id:
            validate_audit_id(audit_id)

        contract, contract_err = self._get_contract()
        if not contract:
            return ExecutionResult(
                command="status",
                result=BootstrapStatus.CONTRACT_INVALID,
                project_id=project_id,
                audit_id=audit_id,
                diagnostics=[f"Contract verification failed: {contract_err}"],
            )

        now = self.clock()

        ver_ok, ver_msg = self.gcloud.get_version()
        if not ver_ok:
            st = BootstrapStatus.GCLOUD_NOT_FOUND if "not found" in ver_msg.lower() else BootstrapStatus.GCLOUD_TOO_OLD
            return ExecutionResult(command="status", result=st, project_id=project_id, audit_id=audit_id, diagnostics=[ver_msg])

        proj_status, _ = self.gcloud.describe_project(project_id)
        if proj_status != BootstrapStatus.ROLE_EXACT_MATCH:
            return ExecutionResult(
                command="status",
                result=proj_status,
                project_id=project_id,
                audit_id=audit_id,
                diagnostics=[f"Project '{project_id}' inaccessible or inactive."],
            )

        role_status, _ = self.gcloud.describe_custom_role(
            project_id=project_id,
            role_id=contract.role_id,
            expected_fingerprint=contract.permission_fingerprint,
        )

        b_status, bindings = self.gcloud.get_invoixy_bindings(
            project_id=project_id,
            role_id=contract.role_id,
            scanner_member=contract.scanner_member,
            clock_now=now,
        )

        role_info = {
            "id": contract.role_id,
            "status": role_status.value,
            "fingerprint": contract.permission_fingerprint,
            "permissions_count": contract.permission_count,
        }

        # Filter bindings by audit_id if supplied
        if audit_id:
            expected_title = build_condition_title(audit_id)
            matching = [b for b in bindings if b.condition_title == expected_title]
        else:
            matching = bindings

        if role_status == BootstrapStatus.ROLE_DRIFT:
            return ExecutionResult(
                command="status",
                result=BootstrapStatus.ROLE_DRIFT,
                project_id=project_id,
                audit_id=audit_id,
                role_info=role_info,
                diagnostics=["Custom role exists but permissions do not match frozen V1 contract."],
            )

        if not matching:
            return ExecutionResult(
                command="status",
                result=BootstrapStatus.NOT_AUTHORIZED,
                project_id=project_id,
                audit_id=audit_id,
                role_info=role_info,
                diagnostics=["No active or expired Invoixy IAM binding found."],
            )

        if len(matching) > 1:
            return ExecutionResult(
                command="status",
                result=BootstrapStatus.MULTIPLE_BINDINGS,
                project_id=project_id,
                audit_id=audit_id,
                role_info=role_info,
                diagnostics=[f"Multiple ({len(matching)}) bindings found for Invoixy scanner."],
            )

        target_b = matching[0]
        if not target_b.is_exact_match:
            return ExecutionResult(
                command="status",
                result=BootstrapStatus.BINDING_DRIFT,
                project_id=project_id,
                audit_id=audit_id,
                role_info=role_info,
                authorization={
                    "role": target_b.role,
                    "condition_title": target_b.condition_title,
                    "condition_expression": target_b.condition_expression,
                },
                diagnostics=["Binding exists but condition expression or role does not match standard contract."],
            )

        auth_dict = {
            "role": target_b.role,
            "condition_title": target_b.condition_title,
            "condition_expression": target_b.condition_expression,
            "expires_at_utc": target_b.expires_at_utc.isoformat() if target_b.expires_at_utc else None,
            "is_expired": target_b.is_expired,
        }

        if target_b.is_expired:
            return ExecutionResult(
                command="status",
                result=BootstrapStatus.EXPIRED_BINDING_PRESENT,
                project_id=project_id,
                audit_id=audit_id,
                role_info=role_info,
                authorization=auth_dict,
                diagnostics=["Binding is present in IAM policy but access has EXPIRED per condition timestamp."],
            )

        return ExecutionResult(
            command="status",
            result=BootstrapStatus.AUTHORIZED,
            project_id=project_id,
            audit_id=audit_id,
            role_info=role_info,
            authorization=auth_dict,
            diagnostics=["Binding is active and valid."],
        )

    def authorize(
        self,
        project_id: str,
        audit_id: str,
        ttl_hours: int = DEFAULT_TTL_HOURS,
        auto_confirm: bool = False,
        confirm_callback: Optional[Callable[[PlanResult], bool]] = None,
    ) -> ExecutionResult:
        """Execute plan and apply mutations with strict verification and partial-failure handling."""
        plan_res = self.plan(project_id=project_id, audit_id=audit_id, ttl_hours=ttl_hours)

        contract, _ = self._get_contract()
        if not contract or plan_res.overall_status == BootstrapStatus.CONTRACT_INVALID:
            return ExecutionResult(
                command="authorize",
                result=BootstrapStatus.CONTRACT_INVALID,
                project_id=project_id,
                audit_id=audit_id,
                diagnostics=plan_res.diagnostics,
            )

        if plan_res.overall_status in {
            BootstrapStatus.GCLOUD_NOT_FOUND,
            BootstrapStatus.GCLOUD_TOO_OLD,
            BootstrapStatus.PROJECT_NOT_ACCESSIBLE,
            BootstrapStatus.PROJECT_NOT_ACTIVE,
            BootstrapStatus.ROLE_DRIFT,
            BootstrapStatus.ROLE_DISABLED,
            BootstrapStatus.BINDING_DRIFT,
            BootstrapStatus.MULTIPLE_BINDINGS,
        }:
            return ExecutionResult(
                command="authorize",
                result=plan_res.overall_status,
                project_id=project_id,
                audit_id=audit_id,
                diagnostics=plan_res.diagnostics,
            )

        if plan_res.overall_status == BootstrapStatus.ALREADY_AUTHORIZED:
            return ExecutionResult(
                command="authorize",
                result=BootstrapStatus.ALREADY_AUTHORIZED,
                project_id=project_id,
                audit_id=audit_id,
                diagnostics=["Exact active binding already exists. Expiry will not be silently extended."],
            )

        # Require Confirmation
        if not auto_confirm:
            if confirm_callback is not None:
                if not confirm_callback(plan_res):
                    return ExecutionResult(
                        command="authorize",
                        result=BootstrapStatus.CANCELLED,
                        project_id=project_id,
                        audit_id=audit_id,
                        diagnostics=["Operation cancelled by user."],
                    )
            else:
                return ExecutionResult(
                    command="authorize",
                    result=BootstrapStatus.CANCELLED,
                    project_id=project_id,
                    audit_id=audit_id,
                    diagnostics=["Confirmation required but not provided."],
                )

        changes: List[str] = []
        role_created_in_this_run = False

        # 1. Role Creation if missing
        if "CREATE_ROLE" in plan_res.proposed_mutations:
            ok, err = self.gcloud.create_custom_role(
                project_id=project_id,
                role_id=contract.role_id,
                title=contract.title,
                description=contract.description,
                stage=contract.stage,
                permissions=contract.included_permissions,
            )
            if not ok:
                return ExecutionResult(
                    command="authorize",
                    result=BootstrapStatus.ROLE_CREATION_FAILED,
                    project_id=project_id,
                    audit_id=audit_id,
                    diagnostics=[f"Role creation failed: {err}"],
                )
            changes.append(f"Created custom role '{contract.role_id}' with {contract.permission_count} permissions.")
            role_created_in_this_run = True

        # 2. Binding Creation
        if "ADD_BINDING" in plan_res.proposed_mutations:
            cond_title = build_condition_title(audit_id)
            cond_desc = build_condition_description()
            cond_expr = build_condition_expression(plan_res.proposed_expiry_utc or (self.clock() + timedelta(hours=ttl_hours)))

            ok, err = self.gcloud.add_iam_policy_binding(
                project_id=project_id,
                role_id=contract.role_id,
                member=contract.scanner_member,
                condition_title=cond_title,
                condition_expression=cond_expr,
                condition_description=cond_desc,
            )
            if not ok:
                if role_created_in_this_run:
                    return ExecutionResult(
                        command="authorize",
                        result=BootstrapStatus.ROLE_CREATED_BINDING_FAILED,
                        project_id=project_id,
                        audit_id=audit_id,
                        changes=changes,
                        diagnostics=[f"Role was created, but IAM policy binding addition failed: {err}"],
                    )
                return ExecutionResult(
                    command="authorize",
                    result=BootstrapStatus.ERROR,
                    project_id=project_id,
                    audit_id=audit_id,
                    changes=changes,
                    diagnostics=[f"Binding addition failed: {err}"],
                )
            changes.append(f"Added conditional IAM binding for '{contract.scanner_member}' with title '{cond_title}'.")

        # 3. Post-Mutation Fresh Verification
        fresh_status = self.status(project_id=project_id, audit_id=audit_id)
        if fresh_status.result != BootstrapStatus.AUTHORIZED:
            return ExecutionResult(
                command="authorize",
                result=BootstrapStatus.AUTHORIZATION_VERIFICATION_FAILED,
                project_id=project_id,
                audit_id=audit_id,
                changes=changes,
                diagnostics=[f"Post-mutation verification failed. Current status: {fresh_status.result.value}"],
            )

        return ExecutionResult(
            command="authorize",
            result=BootstrapStatus.AUTHORIZED,
            project_id=project_id,
            audit_id=audit_id,
            role_info=fresh_status.role_info,
            authorization=fresh_status.authorization,
            changes=changes,
            diagnostics=["Authorization completed and verified successfully."],
        )

    def revoke(
        self,
        project_id: str,
        audit_id: str,
        auto_confirm: bool = False,
        confirm_callback: Optional[Callable[[str], bool]] = None,
    ) -> ExecutionResult:
        """Revoke ONLY the exact audit-specific conditional IAM binding."""
        validate_project_id(project_id)
        validate_audit_id(audit_id)

        contract, contract_err = self._get_contract()
        if not contract:
            return ExecutionResult(
                command="revoke",
                result=BootstrapStatus.CONTRACT_INVALID,
                project_id=project_id,
                audit_id=audit_id,
                diagnostics=[f"Contract verification failed: {contract_err}"],
            )

        status_res = self.status(project_id=project_id, audit_id=audit_id)
        if status_res.result == BootstrapStatus.NOT_AUTHORIZED:
            return ExecutionResult(
                command="revoke",
                result=BootstrapStatus.NOT_AUTHORIZED,
                project_id=project_id,
                audit_id=audit_id,
                diagnostics=["No binding found for this audit ID; already revoked/absent."],
            )

        if status_res.result == BootstrapStatus.MULTIPLE_BINDINGS:
            return ExecutionResult(
                command="revoke",
                result=BootstrapStatus.MULTIPLE_BINDINGS,
                project_id=project_id,
                audit_id=audit_id,
                diagnostics=["Multiple bindings found. Automatic removal refused to prevent ambiguity."],
            )

        if status_res.result not in {BootstrapStatus.AUTHORIZED, BootstrapStatus.EXPIRED_BINDING_PRESENT, BootstrapStatus.BINDING_DRIFT}:
            return ExecutionResult(
                command="revoke",
                result=status_res.result,
                project_id=project_id,
                audit_id=audit_id,
                diagnostics=status_res.diagnostics,
            )

        expected_title = build_condition_title(audit_id)
        auth = status_res.authorization or {}
        cond_expr = auth.get("condition_expression", "")

        # Require Confirmation
        if not auto_confirm:
            if confirm_callback is not None:
                if not confirm_callback(f"Revoke binding '{expected_title}' from project '{project_id}'"):
                    return ExecutionResult(
                        command="revoke",
                        result=BootstrapStatus.CANCELLED,
                        project_id=project_id,
                        audit_id=audit_id,
                        diagnostics=["Revocation cancelled by user."],
                    )
            else:
                return ExecutionResult(
                    command="revoke",
                    result=BootstrapStatus.CANCELLED,
                    project_id=project_id,
                    audit_id=audit_id,
                    diagnostics=["Confirmation required but not provided."],
                )

        ok, err = self.gcloud.remove_iam_policy_binding(
            project_id=project_id,
            role_id=contract.role_id,
            member=contract.scanner_member,
            condition_title=expected_title,
            condition_expression=cond_expr,
            condition_description=build_condition_description(),
        )

        if not ok:
            return ExecutionResult(
                command="revoke",
                result=BootstrapStatus.BINDING_REMOVAL_FAILED,
                project_id=project_id,
                audit_id=audit_id,
                diagnostics=[f"Failed to remove IAM policy binding: {err}"],
            )

        # Fresh verification
        post_status = self.status(project_id=project_id, audit_id=audit_id)
        if post_status.result not in {BootstrapStatus.NOT_AUTHORIZED}:
            return ExecutionResult(
                command="revoke",
                result=BootstrapStatus.ERROR,
                project_id=project_id,
                audit_id=audit_id,
                diagnostics=[f"Post-revoke verification failed. Status is still {post_status.result.value}"],
            )

        return ExecutionResult(
            command="revoke",
            result=BootstrapStatus.NOT_AUTHORIZED,
            project_id=project_id,
            audit_id=audit_id,
            changes=[f"Removed IAM policy binding for title '{expected_title}'. Unbound role '{contract.role_id}' preserved."],
            diagnostics=["Binding removed successfully."],
        )
