# Invoixy Google Cloud Security Review — Client IAM Bootstrap

**Open Source Client Tool (Apache-2.0)**

`invoixy-gcp-bootstrap` is a standalone, client-side utility executed by customer cloud security operators to safely provision and tear down ephemeral, read-only IAM access for an Invoixy Google Cloud Security Review.

---

## 1. Zero-Credential Trust Model

- **Client-Side Execution**: You run this tool on your own workstation or Cloud Shell using your authenticated `gcloud` session.
- **Zero Secrets Uploaded**: Invoixy never asks for service-account JSON keys, credentials, OAuth tokens, or administrative logins.
- **Minimal Read-Only Scope**: Grants exactly one versioned custom role (`InvoixySecurityAuditorV1`) containing 42 control-plane metadata read permissions. Zero access to storage file contents, database tables, VM disks/consoles, or Secret Manager payloads.
- **Strict Time Boundary**: All grants are automatically bound by a Google Cloud IAM Condition (`request.time < timestamp(...)`) with a default TTL of 8 hours (maximum 24 hours). Access ceases automatically at expiration.

---

## 2. Requirements

- Python >= 3.10 (Standard library only; zero third-party dependencies)
- Google Cloud SDK (`gcloud` CLI >= 263.0.0)

---

## 3. Usage & Commands

### A. Plan (Read-Only Simulation)
Preview exactly what IAM role and binding will be created before touching your project:
```bash
python -m invoixy_bootstrap plan --project <PROJECT_ID> --audit-id INV-GCP-YYYY-NNNNNN
```

### B. Authorize (Provision Ephemeral Access)
Interactive command that displays the plan and prompts for confirmation before applying mutations:
```bash
python -m invoixy_bootstrap authorize --project <PROJECT_ID> --audit-id INV-GCP-YYYY-NNNNNN --ttl-hours 8
```
*(Pass `--yes` for automated CI/CD pipelines)*

### C. Status (Read-Only Verification)
Check whether the Invoixy authorization is active, expired, or absent:
```bash
python -m invoixy_bootstrap status --project <PROJECT_ID> --audit-id INV-GCP-YYYY-NNNNNN
```

### D. Revoke (Teardown Access)
Immediately removes the conditional IAM policy binding from your project:
```bash
python -m invoixy_bootstrap revoke --project <PROJECT_ID> --audit-id INV-GCP-YYYY-NNNNNN
```
*(The unbound custom role definition `InvoixySecurityAuditorV1` remains in your project to prevent 30-day GCP role tombstone deletion issues; an unbound custom role grants 0 permissions).*

---

## 4. Machine-Readable Automation

All commands support `--json` output for automated workflows.

---

## 5. Security & Permission Invariants

| Invariant | Enforcement |
| :--- | :--- |
| **Principal Bound** | Strictly `serviceAccount:scanner-v1@invoixy-security-core.iam.gserviceaccount.com` |
| **Custom Role** | Strictly `projects/<PROJECT_ID>/roles/InvoixySecurityAuditorV1` (42 permissions) |
| **Data Plane Access** | 0 storage object read, 0 log entry read, 0 secret payload access |
| **Mutation Rights** | 0 write, 0 create, 0 update, 0 delete permissions |
| **Time Ceiling** | Hard maximum 24-hour expiration condition |
| **Subprocess Execution** | Direct argument arrays (`shell=False`), zero shell interpolation |
