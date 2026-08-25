"""Google Cloud CLI Subprocess Adapter and Mock Test Fixture."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from invoixy_bootstrap.conditions import parse_condition_expression
from invoixy_bootstrap.contract import compute_permissions_fingerprint
from invoixy_bootstrap.models import BindingInfo, BootstrapStatus, ProjectInfo

MIN_GCLOUD_VERSION = "263.0.0"


def _compare_semver(v1_str: str, v2_str: str) -> int:
    """Compare two semantic version strings (e.g. '450.0.0' vs '263.0.0')."""
    def to_nums(s: str) -> List[int]:
        m = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?", s.strip())
        if not m:
            return [0, 0, 0]
        return [int(x) if x is not None else 0 for x in m.groups()]

    n1 = to_nums(v1_str)
    n2 = to_nums(v2_str)
    return (n1 > n2) - (n1 < n2)


class GcloudAdapter(ABC):
    """Abstract interface for Google Cloud CLI operations."""

    @abstractmethod
    def get_version(self) -> Tuple[bool, str]:
        """Return (is_compatible, version_string_or_error)."""
        pass

    @abstractmethod
    def get_active_account(self) -> Optional[str]:
        """Return active authenticated gcloud email or None."""
        pass

    @abstractmethod
    def get_configured_project(self) -> Optional[str]:
        """Return currently configured gcloud project property or None."""
        pass

    @abstractmethod
    def describe_project(self, project_id: str) -> Tuple[BootstrapStatus, Optional[ProjectInfo]]:
        """Fetch project existence, numeric ID, and lifecycle state."""
        pass

    @abstractmethod
    def check_service_enabled(
        self, project_id: str, service_name: str = "iam.googleapis.com"
    ) -> Tuple[BootstrapStatus, bool]:
        """Read-only check whether a service API is enabled on the target project."""
        pass

    @abstractmethod
    def describe_custom_role(
        self, project_id: str, role_id: str, expected_fingerprint: str
    ) -> Tuple[BootstrapStatus, Optional[List[str]]]:
        """Describe custom role and evaluate status against expected fingerprint."""
        pass

    @abstractmethod
    def create_custom_role(
        self,
        project_id: str,
        role_id: str,
        title: str,
        description: str,
        stage: str,
        permissions: List[str],
    ) -> Tuple[bool, Optional[str]]:
        """Create custom role in target project."""
        pass

    @abstractmethod
    def get_invoixy_bindings(
        self,
        project_id: str,
        role_id: str,
        scanner_member: str,
        clock_now: Optional[datetime] = None,
    ) -> Tuple[BootstrapStatus, List[BindingInfo]]:
        """Read IAM policy and return parsed Invoixy bindings."""
        pass

    @abstractmethod
    def add_iam_policy_binding(
        self,
        project_id: str,
        role_id: str,
        member: str,
        condition_title: str,
        condition_expression: str,
        condition_description: str,
    ) -> Tuple[bool, Optional[str]]:
        """Add time-bound conditional IAM policy binding."""
        pass

    @abstractmethod
    def remove_iam_policy_binding(
        self,
        project_id: str,
        role_id: str,
        member: str,
        condition_title: str,
        condition_expression: str,
        condition_description: str,
    ) -> Tuple[bool, Optional[str]]:
        """Remove exact conditional IAM policy binding."""
        pass


class RealGcloudAdapter(GcloudAdapter):
    """Production Gcloud adapter executing safe non-interactive subprocess calls (shell=False)."""

    def __init__(self, gcloud_path: Optional[str] = None):
        self.gcloud_bin = gcloud_path or shutil.which("gcloud")

    def _run_cmd(self, args: List[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
        if not self.gcloud_bin:
            raise RuntimeError("gcloud executable not found in PATH.")
        full_args = [self.gcloud_bin] + args
        child_env = os.environ.copy()
        child_env["CLOUDSDK_CORE_DISABLE_PROMPTS"] = "1"
        return subprocess.run(
            full_args,
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=child_env,
        )

    def get_version(self) -> Tuple[bool, str]:
        if not self.gcloud_bin:
            return False, "gcloud executable not found."
        try:
            res = self._run_cmd(["version", "--format=json"], timeout=10)
            if res.returncode != 0:
                return False, "Failed to inspect gcloud version."
            data = json.loads(res.stdout)
            core_ver = data.get("Google Cloud SDK", "0.0.0")
            if _compare_semver(core_ver, MIN_GCLOUD_VERSION) < 0:
                return False, f"gcloud version {core_ver} is too old (minimum required: {MIN_GCLOUD_VERSION})."
            return True, core_ver
        except Exception as e:
            return False, f"gcloud version check error: {e}"

    def get_active_account(self) -> Optional[str]:
        try:
            res = self._run_cmd(["auth", "list", "--filter=status:ACTIVE", "--format=json"], timeout=10)
            if res.returncode != 0:
                return None
            data = json.loads(res.stdout)
            if isinstance(data, list) and len(data) > 0:
                return data[0].get("account")
            return None
        except Exception:
            return None

    def get_configured_project(self) -> Optional[str]:
        try:
            res = self._run_cmd(["config", "get", "project", "--format=json"], timeout=10)
            if res.returncode != 0:
                return None
            val = json.loads(res.stdout)
            return str(val).strip() if val else None
        except Exception:
            return None

    def describe_project(self, project_id: str) -> Tuple[BootstrapStatus, Optional[ProjectInfo]]:
        try:
            res = self._run_cmd(["projects", "describe", project_id, "--format=json"], timeout=15)
            if res.returncode != 0:
                err_text = res.stderr.lower()
                if "permission" in err_text or "denied" in err_text:
                    return BootstrapStatus.INSUFFICIENT_CALLER_PERMISSION, None
                return BootstrapStatus.PROJECT_NOT_ACCESSIBLE, None
            data = json.loads(res.stdout)
            state = data.get("lifecycleState", "ACTIVE")
            if state != "ACTIVE":
                return BootstrapStatus.PROJECT_NOT_ACTIVE, ProjectInfo(project_id=project_id, lifecycle_state=state)
            return BootstrapStatus.ROLE_EXACT_MATCH, ProjectInfo(
                project_id=data.get("projectId", project_id),
                project_number=data.get("projectNumber"),
                lifecycle_state=state,
            )
        except Exception:
            return BootstrapStatus.PROJECT_NOT_ACCESSIBLE, None

    def check_service_enabled(
        self, project_id: str, service_name: str = "iam.googleapis.com"
    ) -> Tuple[BootstrapStatus, bool]:
        try:
            res = self._run_cmd([
                "services", "list",
                f"--project={project_id}",
                f"--filter=config.name:{service_name}",
                "--format=json",
            ], timeout=15)
            if res.returncode != 0:
                return BootstrapStatus.IAM_API_STATUS_UNKNOWN, False
            data = json.loads(res.stdout)
            if isinstance(data, list) and len(data) > 0:
                for item in data:
                    name = item.get("config", {}).get("name") or item.get("name", "")
                    if service_name in name or item.get("state", "").upper() == "ENABLED":
                        return BootstrapStatus.AUTHORIZED, True
            return BootstrapStatus.IAM_API_DISABLED, False
        except Exception:
            return BootstrapStatus.IAM_API_STATUS_UNKNOWN, False

    def describe_custom_role(
        self, project_id: str, role_id: str, expected_fingerprint: str
    ) -> Tuple[BootstrapStatus, Optional[List[str]]]:
        try:
            res = self._run_cmd(["iam", "roles", "describe", role_id, f"--project={project_id}", "--format=json"], timeout=15)
            if res.returncode != 0:
                if "not found" in res.stderr.lower():
                    return BootstrapStatus.ROLE_MISSING, None
                if "permission" in res.stderr.lower():
                    return BootstrapStatus.INSUFFICIENT_CALLER_PERMISSION, None
                return BootstrapStatus.ROLE_MISSING, None

            data = json.loads(res.stdout)
            if data.get("deleted", False) or data.get("stage") == "DEPRECATED":
                return BootstrapStatus.ROLE_DISABLED, None

            perms = data.get("includedPermissions", [])
            fp = compute_permissions_fingerprint(perms)
            if fp == expected_fingerprint:
                return BootstrapStatus.ROLE_EXACT_MATCH, perms
            return BootstrapStatus.ROLE_DRIFT, perms
        except Exception:
            return BootstrapStatus.ROLE_MISSING, None

    def create_custom_role(
        self,
        project_id: str,
        role_id: str,
        title: str,
        description: str,
        stage: str,
        permissions: List[str],
    ) -> Tuple[bool, Optional[str]]:
        tmp_file = None
        try:
            role_def = {
                "title": title,
                "description": description,
                "stage": stage,
                "includedPermissions": permissions,
            }
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
                json.dump(role_def, f, indent=2)
                tmp_file = Path(f.name)

            res = self._run_cmd([
                "iam", "roles", "create", role_id,
                f"--project={project_id}",
                f"--file={tmp_file}",
                "--quiet",
                "--format=json",
            ], timeout=20)

            if res.returncode != 0:
                return False, res.stderr.strip() or "Role creation command failed."
            return True, None
        except Exception as e:
            return False, str(e)
        finally:
            if tmp_file and tmp_file.exists():
                try:
                    os.unlink(tmp_file)
                except Exception:
                    pass

    def get_invoixy_bindings(
        self,
        project_id: str,
        role_id: str,
        scanner_member: str,
        clock_now: Optional[datetime] = None,
    ) -> Tuple[BootstrapStatus, List[BindingInfo]]:
        now = clock_now or datetime.now(timezone.utc)
        expected_role_path = f"projects/{project_id}/roles/{role_id}"

        try:
            res = self._run_cmd([
                "projects", "get-iam-policy", project_id,
                "--format=json",
            ], timeout=15)
            if res.returncode != 0:
                return BootstrapStatus.INSUFFICIENT_CALLER_PERMISSION, []

            data = json.loads(res.stdout)
            bindings = data.get("bindings", [])
            invoixy_bindings: List[BindingInfo] = []

            for b in bindings:
                b_role = b.get("role", "")
                members = b.get("members", [])
                if scanner_member not in members:
                    continue

                cond = b.get("condition")
                c_title = cond.get("title") if cond else None
                c_expr = cond.get("expression") if cond else None
                c_desc = cond.get("description") if cond else None

                exp_dt = parse_condition_expression(c_expr) if c_expr else None
                is_expired = (now >= exp_dt) if exp_dt else False
                is_exact = (b_role == expected_role_path and exp_dt is not None)

                invoixy_bindings.append(BindingInfo(
                    role=b_role,
                    member=scanner_member,
                    condition_title=c_title,
                    condition_expression=c_expr,
                    condition_description=c_desc,
                    expires_at_utc=exp_dt,
                    is_expired=is_expired,
                    is_exact_match=is_exact,
                ))

            return BootstrapStatus.AUTHORIZED if invoixy_bindings else BootstrapStatus.NOT_AUTHORIZED, invoixy_bindings
        except Exception:
            return BootstrapStatus.INSUFFICIENT_CALLER_PERMISSION, []

    def add_iam_policy_binding(
        self,
        project_id: str,
        role_id: str,
        member: str,
        condition_title: str,
        condition_expression: str,
        condition_description: str,
    ) -> Tuple[bool, Optional[str]]:
        expected_role_path = f"projects/{project_id}/roles/{role_id}"
        cond_str = f"expression={condition_expression},title={condition_title},description={condition_description}"
        try:
            res = self._run_cmd([
                "projects", "add-iam-policy-binding", project_id,
                f"--member={member}",
                f"--role={expected_role_path}",
                f"--condition={cond_str}",
                "--quiet",
                "--format=json",
            ], timeout=20)
            if res.returncode != 0:
                return False, res.stderr.strip() or "Failed to add IAM policy binding."
            return True, None
        except Exception as e:
            return False, str(e)

    def remove_iam_policy_binding(
        self,
        project_id: str,
        role_id: str,
        member: str,
        condition_title: str,
        condition_expression: str,
        condition_description: str,
    ) -> Tuple[bool, Optional[str]]:
        expected_role_path = f"projects/{project_id}/roles/{role_id}"
        cond_str = f"expression={condition_expression},title={condition_title},description={condition_description}"
        try:
            res = self._run_cmd([
                "projects", "remove-iam-policy-binding", project_id,
                f"--member={member}",
                f"--role={expected_role_path}",
                f"--condition={cond_str}",
                "--quiet",
                "--format=json",
            ], timeout=20)
            if res.returncode != 0:
                return False, res.stderr.strip() or "Failed to remove IAM policy binding."
            return True, None
        except Exception as e:
            return False, str(e)


class FakeGcloudAdapter(GcloudAdapter):
    """In-memory mock adapter for 100% offline unit and integration testing."""

    def __init__(
        self,
        version: str = "450.0.0",
        active_account: Optional[str] = "operator@customer.com",
        configured_project: Optional[str] = "target-project-id",
        project_accessible: bool = True,
        project_active: bool = True,
        iam_api_enabled: bool = True,
        fail_service_check: bool = False,
    ):
        self.version = version
        self.active_account = active_account
        self.configured_project = configured_project
        self.project_accessible = project_accessible
        self.project_active = project_active
        self.iam_api_enabled = iam_api_enabled
        self.fail_service_check = fail_service_check

        # State storage
        self.roles: Dict[str, Dict[str, Any]] = {}
        self.bindings: Dict[str, List[Dict[str, Any]]] = {}

        # Simulation failure toggles
        self.fail_role_creation = False
        self.fail_binding_addition = False
        self.fail_binding_removal = False
        self.fail_post_verify = False
        self.caller_has_permissions = True

        # Mutation call history for mechanical assertion
        self.call_history: List[Tuple[str, Dict[str, Any]]] = []

    def get_version(self) -> Tuple[bool, str]:
        if _compare_semver(self.version, MIN_GCLOUD_VERSION) < 0:
            return False, f"gcloud version {self.version} is too old (minimum required: {MIN_GCLOUD_VERSION})."
        return True, self.version

    def get_active_account(self) -> Optional[str]:
        return self.active_account

    def get_configured_project(self) -> Optional[str]:
        return self.configured_project

    def describe_project(self, project_id: str) -> Tuple[BootstrapStatus, Optional[ProjectInfo]]:
        if not self.caller_has_permissions:
            return BootstrapStatus.INSUFFICIENT_CALLER_PERMISSION, None
        if not self.project_accessible:
            return BootstrapStatus.PROJECT_NOT_ACCESSIBLE, None
        if not self.project_active:
            return BootstrapStatus.PROJECT_NOT_ACTIVE, ProjectInfo(project_id=project_id, lifecycle_state="DELETE_REQUESTED")
        return BootstrapStatus.ROLE_EXACT_MATCH, ProjectInfo(project_id=project_id, project_number="123456789012", lifecycle_state="ACTIVE")

    def check_service_enabled(
        self, project_id: str, service_name: str = "iam.googleapis.com"
    ) -> Tuple[BootstrapStatus, bool]:
        if not self.caller_has_permissions or self.fail_service_check:
            return BootstrapStatus.IAM_API_STATUS_UNKNOWN, False
        if self.iam_api_enabled:
            return BootstrapStatus.AUTHORIZED, True
        return BootstrapStatus.IAM_API_DISABLED, False

    def describe_custom_role(
        self, project_id: str, role_id: str, expected_fingerprint: str
    ) -> Tuple[BootstrapStatus, Optional[List[str]]]:
        if not self.caller_has_permissions:
            return BootstrapStatus.INSUFFICIENT_CALLER_PERMISSION, None
        key = f"{project_id}/{role_id}"
        role = self.roles.get(key)
        if not role:
            return BootstrapStatus.ROLE_MISSING, None
        if role.get("deleted") or role.get("stage") == "DEPRECATED":
            return BootstrapStatus.ROLE_DISABLED, None

        perms = role.get("includedPermissions", [])
        fp = compute_permissions_fingerprint(perms)
        if fp == expected_fingerprint:
            return BootstrapStatus.ROLE_EXACT_MATCH, perms
        return BootstrapStatus.ROLE_DRIFT, perms

    def create_custom_role(
        self,
        project_id: str,
        role_id: str,
        title: str,
        description: str,
        stage: str,
        permissions: List[str],
    ) -> Tuple[bool, Optional[str]]:
        self.call_history.append(("create_custom_role", {
            "project_id": project_id,
            "role_id": role_id,
            "title": title,
            "permissions_count": len(permissions),
        }))
        if self.fail_role_creation:
            return False, "Simulated role creation permission failure"

        key = f"{project_id}/{role_id}"
        self.roles[key] = {
            "title": title,
            "description": description,
            "stage": stage,
            "includedPermissions": permissions,
            "deleted": False,
        }
        return True, None

    def get_invoixy_bindings(
        self,
        project_id: str,
        role_id: str,
        scanner_member: str,
        clock_now: Optional[datetime] = None,
    ) -> Tuple[BootstrapStatus, List[BindingInfo]]:
        if not self.caller_has_permissions:
            return BootstrapStatus.INSUFFICIENT_CALLER_PERMISSION, []

        now = clock_now or datetime.now(timezone.utc)
        expected_role_path = f"projects/{project_id}/roles/{role_id}"
        raw_list = self.bindings.get(project_id, [])

        invoixy_bindings: List[BindingInfo] = []
        for b in raw_list:
            if scanner_member not in b.get("members", []):
                continue
            b_role = b.get("role", "")
            cond = b.get("condition")
            c_title = cond.get("title") if cond else None
            c_expr = cond.get("expression") if cond else None
            c_desc = cond.get("description") if cond else None

            exp_dt = parse_condition_expression(c_expr) if c_expr else None
            is_expired = (now >= exp_dt) if exp_dt else False
            is_exact = (b_role == expected_role_path and exp_dt is not None)

            invoixy_bindings.append(BindingInfo(
                role=b_role,
                member=scanner_member,
                condition_title=c_title,
                condition_expression=c_expr,
                condition_description=c_desc,
                expires_at_utc=exp_dt,
                is_expired=is_expired,
                is_exact_match=is_exact,
            ))

        return BootstrapStatus.AUTHORIZED if invoixy_bindings else BootstrapStatus.NOT_AUTHORIZED, invoixy_bindings

    def add_iam_policy_binding(
        self,
        project_id: str,
        role_id: str,
        member: str,
        condition_title: str,
        condition_expression: str,
        condition_description: str,
    ) -> Tuple[bool, Optional[str]]:
        self.call_history.append(("add_iam_policy_binding", {
            "project_id": project_id,
            "role_id": role_id,
            "member": member,
            "condition_title": condition_title,
            "condition_expression": condition_expression,
        }))
        if self.fail_binding_addition:
            return False, "Simulated IAM policy concurrency / permission failure"

        expected_role_path = f"projects/{project_id}/roles/{role_id}"
        if project_id not in self.bindings:
            self.bindings[project_id] = []

        if not self.fail_post_verify:
            self.bindings[project_id].append({
                "role": expected_role_path,
                "members": [member],
                "condition": {
                    "title": condition_title,
                    "expression": condition_expression,
                    "description": condition_description,
                },
            })
        return True, None

    def remove_iam_policy_binding(
        self,
        project_id: str,
        role_id: str,
        member: str,
        condition_title: str,
        condition_expression: str,
        condition_description: str,
    ) -> Tuple[bool, Optional[str]]:
        self.call_history.append(("remove_iam_policy_binding", {
            "project_id": project_id,
            "role_id": role_id,
            "member": member,
            "condition_title": condition_title,
        }))
        if self.fail_binding_removal:
            return False, "Simulated IAM binding removal failure"

        expected_role_path = f"projects/{project_id}/roles/{role_id}"
        raw_list = self.bindings.get(project_id, [])
        new_list = []
        for b in raw_list:
            if b.get("role") == expected_role_path and member in b.get("members", []):
                cond = b.get("condition", {})
                if cond.get("title") == condition_title:
                    continue  # Remove
            new_list.append(b)
        self.bindings[project_id] = new_list
        return True, None
