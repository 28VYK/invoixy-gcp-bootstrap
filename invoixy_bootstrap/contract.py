"""Frozen Public IAM Role Contract Loader and Invariant Verifier."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import List, Optional

from invoixy_bootstrap.models import RoleContract

EXPECTED_VERSION = 1
EXPECTED_ROLE_ID = "InvoixySecurityAuditorV1"
EXPECTED_SCANNER_MEMBER = "serviceAccount:scanner-v1@invoixy-security-core.iam.gserviceaccount.com"
EXPECTED_PERMISSION_COUNT = 42
EXPECTED_FINGERPRINT = "a8a1e6af1243e26068bc95d7f2dfde8453b9b647a13db0940d2eabf4a192c201"

# Hard Forbidden Capability Keywords & Identifiers
FORBIDDEN_PERMISSIONS: List[str] = [
    "logging.logEntries.list",
    "storage.objects.get",
    "secretmanager.versions.access",
    "compute.instances.getSerialPortOutput",
    "iam.serviceAccounts.actAs",
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.signBlob",
    "iam.serviceAccounts.signJwt",
]

FORBIDDEN_SUFFIXES = (
    ".setIamPolicy",
    ".create",
    ".delete",
    ".update",
    ".write",
)


class ContractInvalidError(RuntimeError):
    """Raised when the public role contract fails cryptographic or structural invariants."""
    pass


def compute_permissions_fingerprint(permissions: List[str]) -> str:
    """Compute canonical SHA-256 fingerprint over sorted compact JSON permission array."""
    canonical_json = json.dumps(sorted(permissions), separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def load_auditor_contract(contract_path: Optional[Path | str] = None) -> RoleContract:
    """
    Load and cryptographically verify contracts/auditor_role_v1.json.
    Fails closed on any structural, count, fingerprint, or forbidden capability mismatch.
    """
    if contract_path is None:
        contract_path = Path(__file__).resolve().parent.parent / "contracts" / "auditor_role_v1.json"
    else:
        contract_path = Path(contract_path)

    if not contract_path.exists():
        raise ContractInvalidError(f"Contract file not found: {contract_path}")

    try:
        with open(contract_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        raise ContractInvalidError(f"Failed to read contract JSON: {e}") from e

    # 1. Structural Checks
    version = data.get("contract_version")
    if version != EXPECTED_VERSION:
        raise ContractInvalidError(f"Contract version mismatch: {version} (expected {EXPECTED_VERSION})")

    role_id = data.get("role_id")
    if role_id != EXPECTED_ROLE_ID:
        raise ContractInvalidError(f"Role ID mismatch: {role_id} (expected {EXPECTED_ROLE_ID})")

    scanner_member = data.get("scanner_member")
    if scanner_member != EXPECTED_SCANNER_MEMBER:
        raise ContractInvalidError(f"Scanner member mismatch: {scanner_member} (expected {EXPECTED_SCANNER_MEMBER})")

    perms = data.get("included_permissions")
    if not isinstance(perms, list):
        raise ContractInvalidError("included_permissions must be a list")

    if len(perms) != EXPECTED_PERMISSION_COUNT:
        raise ContractInvalidError(f"Permission count mismatch: {len(perms)} (expected {EXPECTED_PERMISSION_COUNT})")

    if len(set(perms)) != EXPECTED_PERMISSION_COUNT:
        raise ContractInvalidError("Duplicate permissions detected in contract")

    # 2. Fingerprint Check
    calc_fp = compute_permissions_fingerprint(perms)
    declared_fp = data.get("permission_fingerprint")
    if calc_fp != EXPECTED_FINGERPRINT or declared_fp != EXPECTED_FINGERPRINT:
        raise ContractInvalidError(
            f"Cryptographic fingerprint mismatch: calculated {calc_fp}, declared {declared_fp}, expected {EXPECTED_FINGERPRINT}"
        )

    # 3. Forbidden Capability Invariants Check
    for p in perms:
        if p in FORBIDDEN_PERMISSIONS:
            raise ContractInvalidError(f"Forbidden capability detected in contract: {p}")
        if any(p.endswith(sfx) for sfx in FORBIDDEN_SUFFIXES):
            raise ContractInvalidError(f"Forbidden mutation/write capability detected in contract: {p}")

    return RoleContract(
        contract_version=version,
        role_id=role_id,
        title=data.get("title", "InvoixySecurityAuditor"),
        description=data.get("description", ""),
        stage=data.get("stage", "GA"),
        scanner_member=scanner_member,
        permission_count=len(perms),
        fingerprint_algorithm=data.get("fingerprint_algorithm", "sha256"),
        permission_fingerprint=declared_fp,
        included_permissions=sorted(perms),
    )
