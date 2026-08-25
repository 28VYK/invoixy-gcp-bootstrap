"""Unit tests for conditions, CEL formatting, and input validators."""

import unittest
from datetime import datetime, timezone

from invoixy_bootstrap.conditions import (
    ValidationError,
    build_condition_description,
    build_condition_expression,
    build_condition_title,
    parse_condition_expression,
    validate_audit_id,
    validate_project_id,
    validate_ttl_hours,
)


class TestConditions(unittest.TestCase):
    def test_audit_id_validation(self):
        validate_audit_id("INV-GCP-2026-000001")
        validate_audit_id("INV-GCP-2025-999999")

        for bad in ["INV-GCP-26-000001", "AUDIT-001", "INV-GCP-2026-1", "INV-GCP-2026-000001; rm -rf"]:
            with self.assertRaises(ValidationError):
                validate_audit_id(bad)

    def test_project_id_validation(self):
        validate_project_id("my-test-project")
        validate_project_id("customer-prod-01")

        for bad in ["proj", "UPPERCASE", "123-start-num", "my_proj_with_underscore", "proj;evil", "-start-dash"]:
            with self.assertRaises(ValidationError):
                validate_project_id(bad)

    def test_ttl_hours_validation(self):
        self.assertEqual(validate_ttl_hours(1), 1)
        self.assertEqual(validate_ttl_hours(8), 8)
        self.assertEqual(validate_ttl_hours(24), 24)

        for bad in [0, -1, 25, 100, "abc", None]:
            with self.assertRaises(ValidationError):
                validate_ttl_hours(bad)

    def test_condition_expression_roundtrip(self):
        dt = datetime(2026, 8, 25, 18, 30, 0, tzinfo=timezone.utc)
        expr = build_condition_expression(dt)
        self.assertEqual(expr, 'request.time < timestamp("2026-08-25T18:30:00Z")')

        parsed = parse_condition_expression(expr)
        self.assertEqual(parsed, dt)

    def test_condition_title_formatting(self):
        title = build_condition_title("INV-GCP-2026-000123")
        self.assertEqual(title, "invoixy-security-review-v1-INV-GCP-2026-000123")
        self.assertEqual(build_condition_description(), "Temporary Invoixy Google Cloud Security Review access.")


if __name__ == "__main__":
    unittest.main()
