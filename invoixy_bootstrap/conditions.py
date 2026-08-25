"""Validation, CEL Condition formatting, and parsing for Invoixy IAM Bindings."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

AUDIT_ID_REGEX = re.compile(r"^INV-GCP-\d{4}-\d{6}$")
PROJECT_ID_REGEX = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
CONDITION_EXPR_REGEX = re.compile(r"^request\.time\s*<\s*timestamp\(\"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\"\)$")

DEFAULT_TTL_HOURS = 8
MIN_TTL_HOURS = 1
MAX_TTL_HOURS = 24


class ValidationError(ValueError):
    """Raised when input arguments fail security/syntactic validation."""
    pass


def validate_audit_id(audit_id: str) -> None:
    """Validate that audit_id strictly conforms to canonical INV-GCP-YYYY-NNNNNN."""
    if not isinstance(audit_id, str) or not AUDIT_ID_REGEX.match(audit_id):
        raise ValidationError(
            f"Invalid Audit ID: '{audit_id}'. Expected canonical format: INV-GCP-YYYY-NNNNNN (e.g. INV-GCP-2026-000001)."
        )


def validate_project_id(project_id: str) -> None:
    """Validate Google Cloud Project ID according to strict GCP naming rules."""
    if not isinstance(project_id, str) or not PROJECT_ID_REGEX.match(project_id):
        raise ValidationError(
            f"Invalid Project ID: '{project_id}'. Must be 6-30 characters, lowercase letters, digits, and hyphens."
        )


def validate_ttl_hours(ttl_hours: int | str) -> int:
    """Validate TTL hours integer range [1, 24]."""
    try:
        ttl = int(ttl_hours)
    except (ValueError, TypeError):
        raise ValidationError(f"Invalid TTL hours: '{ttl_hours}'. Must be an integer between 1 and 24.")

    if ttl < MIN_TTL_HOURS or ttl > MAX_TTL_HOURS:
        raise ValidationError(f"TTL hours out of allowed range [{MIN_TTL_HOURS}, {MAX_TTL_HOURS}]. Received: {ttl}.")
    return ttl


def build_condition_title(audit_id: str) -> str:
    """Build deterministic, privacy-safe IAM Condition Title."""
    validate_audit_id(audit_id)
    return f"invoixy-security-review-v1-{audit_id}"


def build_condition_description() -> str:
    """Build fixed condition description."""
    return "Temporary Invoixy Google Cloud Security Review access."


def format_canonical_utc_timestamp(dt: datetime) -> str:
    """
    Format datetime strictly as UTC RFC3339 timestamp with seconds precision and literal 'Z'.
    Truncates microseconds (never rounds upward).
    """
    if dt.tzinfo is None:
        raise ValidationError("Naive datetime rejected; explicit UTC timezone required.")
    dt_utc = dt.astimezone(timezone.utc).replace(microsecond=0)
    return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_condition_expression(expiry_utc: datetime) -> str:
    """Format CEL request.time timestamp expression in UTC with seconds precision."""
    formatted = format_canonical_utc_timestamp(expiry_utc)
    return f'request.time < timestamp("{formatted}")'


def parse_condition_expression(expr: str) -> Optional[datetime]:
    """
    Parse exact canonical CEL timestamp expression into UTC datetime.
    Returns None if expression is malformed or does not match canonical syntax.
    """
    if not expr:
        return None
    match = CONDITION_EXPR_REGEX.match(expr.strip())
    if not match:
        return None
    ts_str = match.group(1)
    try:
        dt = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None
