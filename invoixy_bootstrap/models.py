"""Data models and deterministic status enumerations for Invoixy Bootstrap."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class BootstrapStatus(str, Enum):
    """Deterministic operational status states."""
    # Primary Terminal States
    AUTHORIZED = "AUTHORIZED"
    EXPIRED_BINDING_PRESENT = "EXPIRED_BINDING_PRESENT"
    NOT_AUTHORIZED = "NOT_AUTHORIZED"
    ALREADY_AUTHORIZED = "ALREADY_AUTHORIZED"

    # Role Specific States
    ROLE_MISSING = "ROLE_MISSING"
    ROLE_EXACT_MATCH = "ROLE_EXACT_MATCH"
    ROLE_DRIFT = "ROLE_DRIFT"
    ROLE_DISABLED = "ROLE_DISABLED"

    # Binding Specific States
    BINDING_MISSING = "BINDING_MISSING"
    BINDING_DRIFT = "BINDING_DRIFT"
    MULTIPLE_EXACT_BINDINGS = "MULTIPLE_EXACT_BINDINGS"
    MULTIPLE_AMBIGUOUS_BINDINGS = "MULTIPLE_AMBIGUOUS_BINDINGS"
    MULTIPLE_BINDINGS = "MULTIPLE_BINDINGS"

    # Environment / Access States
    PROJECT_NOT_ACCESSIBLE = "PROJECT_NOT_ACCESSIBLE"
    PROJECT_NOT_ACTIVE = "PROJECT_NOT_ACTIVE"
    NOT_AUTHENTICATED = "NOT_AUTHENTICATED"
    INSUFFICIENT_CALLER_PERMISSION = "INSUFFICIENT_CALLER_PERMISSION"
    GCLOUD_NOT_FOUND = "GCLOUD_NOT_FOUND"
    GCLOUD_TOO_OLD = "GCLOUD_TOO_OLD"
    CONTRACT_INVALID = "CONTRACT_INVALID"
    IAM_API_DISABLED = "IAM_API_DISABLED"
    IAM_API_STATUS_UNKNOWN = "IAM_API_STATUS_UNKNOWN"

    # Mutation Failure States
    ROLE_CREATION_FAILED = "ROLE_CREATION_FAILED"
    ROLE_CREATED_BINDING_FAILED = "ROLE_CREATED_BINDING_FAILED"
    AUTHORIZATION_VERIFICATION_FAILED = "AUTHORIZATION_VERIFICATION_FAILED"
    BINDING_REMOVAL_FAILED = "BINDING_REMOVAL_FAILED"
    CANCELLED = "CANCELLED"
    ERROR = "ERROR"


@dataclass(frozen=True)
class RoleContract:
    """Frozen public custom IAM role definition."""
    contract_version: int
    role_id: str
    title: str
    description: str
    stage: str
    scanner_member: str
    permission_count: int
    fingerprint_algorithm: str
    permission_fingerprint: str
    included_permissions: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ProjectInfo:
    """Target Google Cloud Project metadata."""
    project_id: str
    project_number: Optional[str] = None
    lifecycle_state: str = "ACTIVE"


@dataclass(frozen=True)
class BindingInfo:
    """Information about an Invoixy IAM binding."""
    role: str
    member: str
    condition_title: Optional[str] = None
    condition_expression: Optional[str] = None
    condition_description: Optional[str] = None
    expires_at_utc: Optional[datetime] = None
    is_expired: bool = False
    is_exact_match: bool = False


@dataclass
class PlanResult:
    """Output of a read-only plan evaluation."""
    contract_version: int
    role_id: str
    permission_fingerprint: str
    scanner_member: str
    audit_id: str
    project_id: str
    active_account: Optional[str]
    configured_project: Optional[str]
    project_mismatch: bool
    role_status: BootstrapStatus
    binding_status: BootstrapStatus
    overall_status: BootstrapStatus
    proposed_expiry_utc: Optional[datetime]
    proposed_mutations: List[str] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        from invoixy_bootstrap.conditions import format_canonical_utc_timestamp
        return {
            "schema_version": 1,
            "command": "plan",
            "contract_version": self.contract_version,
            "role_id": self.role_id,
            "permission_fingerprint": self.permission_fingerprint,
            "scanner_member": self.scanner_member,
            "audit_id": self.audit_id,
            "project_id": self.project_id,
            "active_account": self.active_account,
            "configured_project": self.configured_project,
            "project_mismatch": self.project_mismatch,
            "role_status": self.role_status.value,
            "binding_status": self.binding_status.value,
            "overall_status": self.overall_status.value,
            "proposed_expiry_utc": format_canonical_utc_timestamp(self.proposed_expiry_utc) if self.proposed_expiry_utc else None,
            "proposed_mutations": self.proposed_mutations,
            "diagnostics": self.diagnostics,
        }


@dataclass
class ExecutionResult:
    """Unified result envelope for plan, authorize, status, and revoke."""
    schema_version: int = 1
    command: str = "status"
    result: BootstrapStatus = BootstrapStatus.NOT_AUTHORIZED
    project_id: str = ""
    audit_id: Optional[str] = None
    role_info: Optional[Dict[str, Any]] = None
    authorization: Optional[Dict[str, Any]] = None
    changes: List[str] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)
    execution_timestamp_utc: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        from datetime import timezone
        from invoixy_bootstrap.conditions import format_canonical_utc_timestamp
        exec_ts = self.execution_timestamp_utc or format_canonical_utc_timestamp(datetime.now(timezone.utc))
        return {
            "schema_version": self.schema_version,
            "command": self.command,
            "result": self.result.value,
            "project_id": self.project_id,
            "audit_id": self.audit_id,
            "role": self.role_info,
            "authorization": self.authorization,
            "changes": self.changes,
            "diagnostics": self.diagnostics,
            "execution_timestamp_utc": exec_ts,
        }
