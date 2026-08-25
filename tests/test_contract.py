"""Unit tests for frozen public IAM role contract."""

import json
import tempfile
import unittest
from pathlib import Path

from invoixy_bootstrap.contract import (
    EXPECTED_FINGERPRINT,
    EXPECTED_PERMISSION_COUNT,
    EXPECTED_ROLE_ID,
    EXPECTED_SCANNER_MEMBER,
    ContractInvalidError,
    compute_permissions_fingerprint,
    load_auditor_contract,
)


class TestContract(unittest.TestCase):
    def test_official_contract_loads_valid(self):
        c = load_auditor_contract()
        self.assertEqual(c.contract_version, 1)
        self.assertEqual(c.role_id, EXPECTED_ROLE_ID)
        self.assertEqual(c.scanner_member, EXPECTED_SCANNER_MEMBER)
        self.assertEqual(c.permission_count, EXPECTED_PERMISSION_COUNT)
        self.assertEqual(len(c.included_permissions), EXPECTED_PERMISSION_COUNT)
        self.assertEqual(c.permission_fingerprint, EXPECTED_FINGERPRINT)
        self.assertEqual(compute_permissions_fingerprint(c.included_permissions), EXPECTED_FINGERPRINT)

    def test_contract_rejects_modified_permission(self):
        c = load_auditor_contract()
        data = c.to_dict()
        data["included_permissions"][0] = "storage.objects.get"  # Forbidden

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(data, f)
            tmp_p = f.name

        try:
            with self.assertRaises(ContractInvalidError):
                load_auditor_contract(tmp_p)
        finally:
            Path(tmp_p).unlink(missing_ok=True)

    def test_contract_rejects_missing_permission_or_count_mismatch(self):
        c = load_auditor_contract()
        data = c.to_dict()
        data["included_permissions"] = data["included_permissions"][:-1]  # 41 perms

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(data, f)
            tmp_p = f.name

        try:
            with self.assertRaises(ContractInvalidError):
                load_auditor_contract(tmp_p)
        finally:
            Path(tmp_p).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
