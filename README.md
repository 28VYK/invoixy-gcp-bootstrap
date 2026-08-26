# Invoixy Google Cloud Bootstrap

**Client-side IAM bootstrap and ephemeral permission lifecycle manager for Invoixy Google Cloud Security Review.**

`invoixy-gcp-bootstrap` is an open-source, client-side utility executed directly by customer cloud security operators on their own workstations or Google Cloud Shell to safely authorize, inspect, and revoke temporary, read-only IAM access for an authorized Invoixy Security Review.

---

## 1. What This Tool Does

When you engage Invoixy for a Google Cloud Security Review, our scanner requires temporary read-only access to control-plane metadata (such as IAM policy structures, firewall rules, and encryption settings) to evaluate security posture against CIS benchmarks and cloud security best practices.

This tool automates the client-side authorization lifecycle:
1. **Interactive Assistant**: Guides you through authorizing an engagement with explicit confirmation and zero manual IAM JSON policy editing.
2. **Deterministic Custom Role**: Provisions the exact, versioned `InvoixySecurityAuditorV1` role containing 42 metadata-read permissions.
3. **Time-Bound Conditional Binding**: Grants temporary access constrained by an automated Google Cloud IAM Condition (`request.time < timestamp(...)`) with a default TTL of 8 hours (maximum 24 hours).
4. **Clean Revocation**: Allows immediate removal of the conditional binding at any time.

---

## 2. Security & Trust Model

Invoixy operates under a strict **No-Customer-Secrets** and **Zero-Data-Access** security architecture:

- **Client-Side Execution**: You execute this tool locally using your existing, authenticated `gcloud` session.
- **No Customer Secrets or Keys**: Invoixy never requests or accepts Google Service Account JSON keys, long-lived API tokens, OAuth refresh credentials, or administrative passwords. The scanner authenticates via short-lived Workload Identity Federation credentials, and bootstrap never creates service-account keys.
- **Control Plane Only (Zero Data-Plane Access)**: The 42 granted permissions allow viewing configuration metadata only. The role contains:
  - **Zero** storage object read permissions (`storage.objects.get` is strictly prohibited).
  - **Zero** secret payload access (`secretmanager.versions.access` is strictly prohibited).
  - **Zero** log payload extraction (`logging.logEntries.list` is strictly prohibited).
  - **Zero** VM console/disk access (`compute.instances.getSerialPortOutput` is strictly prohibited).
  - **Zero** service account impersonation (`iam.serviceAccounts.actAs`, `getAccessToken`, `signBlob`, `signJwt` are strictly prohibited).
  - **Zero** create, update, delete, write, or `setIamPolicy` permissions.
- **Automatic Expiration**: When the configured TTL expires (e.g. 8 hours), Google Cloud IAM automatically invalidates the binding. Access ceases immediately without requiring manual operator intervention.
- **Fail-Closed Verification**: The tool cryptographically verifies the role definition against its frozen SHA-256 fingerprint (`a8a1e6af...`). If any permission drifts or is missing, authorization immediately blocks.
- **Zero Automated API Enablement**: The Identity and Access Management API (`iam.googleapis.com`) must already be enabled on your project. The bootstrap tool will never attempt `services enable` in your environment.

---

## 3. What This Tool Does NOT Do

To maintain absolute safety in customer environments, this tool:
- **Does NOT** enable any Google Cloud APIs.
- **Does NOT** create or download service-account keys.
- **Does NOT** grant Owner, Editor, or any broad administrative roles.
- **Does NOT** read, export, or modify workloads, database tables, or stored customer files.
- **Does NOT** create billable compute or storage resources in your project.
- **Does NOT** modify or replace existing IAM bindings unrelated to the specified Invoixy engagement.

---

## 4. Prerequisites

- **Python**: `>= 3.10` (Standard library only; zero third-party dependencies).
- **Google Cloud SDK**: `gcloud` CLI installed and authenticated (`gcloud auth login`). Minimum required version: `263.0.0`.
- **Target Project Permissions**: The operator running this tool requires standard project IAM administration rights (`roles/resourcemanager.projectIamAdmin` or `roles/owner`) on the target project to create the custom role and conditional binding.

---

## 5. Installation

### After Public Release (via pipx / pip):
```bash
pipx install invoixy-gcp-bootstrap
```
*Or via standard pip in a virtual environment:*
```bash
pip install invoixy-gcp-bootstrap
```

### Local Development / Direct Execution:
Clone the repository and run directly:
```bash
python -m invoixy_bootstrap
```

---

## 6. Interactive Usage (Recommended)

Running `invoixy-gcp-bootstrap` with no arguments automatically launches the interactive terminal assistant:

```bash
invoixy-gcp-bootstrap
```

### Interactive Flow:
```text
============================================================
Invoixy Google Cloud Security Review
Temporary Google Cloud authorization assistant
============================================================
Google Cloud CLI: detected (513.0.0)
Active account:   operator@example.com

Select an action:
  1. Authorize a security review
  2. Check authorization status
  3. Revoke authorization
  4. Exit

Select an option [1-4]: 1

--- 1. Authorize Security Review ---
Google Cloud Project ID: customer-prod-vpc
Invoixy Audit ID (e.g. INV-GCP-2026-000001): INV-GCP-2026-000042
Access duration in hours [8]: 8

Evaluating authorization plan...

============================================================
PROPOSED AUTHORIZATION PLAN
============================================================
Target Project:          customer-prod-vpc
Audit Engagement ID:     INV-GCP-2026-000042
Custom Role ID:          InvoixySecurityAuditorV1 (42 permissions)
Role Action:             Create new custom role
Scanner Identity:        serviceAccount:scanner-v1@invoixy-security-core.iam.gserviceaccount.com
Access Duration:         8 hours
Calculated Expiry (UTC): 2026-08-26T18:00:00Z
------------------------------------------------------------
What this will do:
  - Create or reuse the exact InvoixySecurityAuditorV1 role.
  - Add one temporary conditional IAM binding for the Invoixy scanner.

What this will NOT do:
  - Enable Google Cloud APIs.
  - Create service-account keys.
  - Grant Owner or Editor.
  - Modify workloads or stored application data.
  - Create resources in the project.
============================================================

Continue with authorization? [y/N]: y

Applying authorization...

>>> AUTHORIZATION SUCCESSFUL <<<
  [+] Created custom role 'InvoixySecurityAuditorV1' with 42 permissions.
  [+] Added conditional IAM binding for 'serviceAccount:scanner-v1@invoixy-security-core.iam.gserviceaccount.com' expiring at 2026-08-26T18:00:00Z.
```

---

## 7. Advanced CLI Usage & Automation

All operations are available as scriptable CLI subcommands. Non-interactive pipelines can supply `--yes` to bypass prompts and `--json` for machine-readable output.

### A. Preview Plan (Read-Only Simulation)
Preview planned IAM mutations without making any changes:
```bash
invoixy-gcp-bootstrap plan --project <PROJECT_ID> --audit-id INV-GCP-YYYY-NNNNNN [--ttl-hours 8] [--json]
```

### B. Authorize (Provision Ephemeral Access)
```bash
invoixy-gcp-bootstrap authorize --project <PROJECT_ID> --audit-id INV-GCP-YYYY-NNNNNN [--ttl-hours 8] [--yes] [--json]
```

### C. Inspect Status
Check whether engagement access is active, expired, or absent:
```bash
invoixy-gcp-bootstrap status --project <PROJECT_ID> [--audit-id INV-GCP-YYYY-NNNNNN] [--json]
```

### D. Revoke Access
Immediately remove the conditional IAM binding:
```bash
invoixy-gcp-bootstrap revoke --project <PROJECT_ID> --audit-id INV-GCP-YYYY-NNNNNN [--yes] [--json]
```
*(Note: The custom role definition `InvoixySecurityAuditorV1` remains in your project to avoid Google Cloud's 30-day custom role deletion tombstones. An unbound custom role grants zero permissions).*

---

## 8. Role Contract & Auditability

The custom role contract is cryptographically frozen:
- **Role ID**: `InvoixySecurityAuditorV1`
- **Title**: `InvoixySecurityAuditor`
- **Permission Count**: Exactly `42`
- **SHA-256 Fingerprint**: `a8a1e6af1243e26068bc95d7f2dfde8453b9b647a13db0940d2eabf4a192c201`
- **Scanner Principal**: `serviceAccount:scanner-v1@invoixy-security-core.iam.gserviceaccount.com`

The complete permission list is located in `contracts/auditor_role_v1.json` and is audited on every execution.

---

## 9. Subprocess & Automation Safety

All Google Cloud operations executed by this tool enforce:
- Direct argument vector invocation (`shell=False`).
- Prompt suppression (`CLOUDSDK_CORE_DISABLE_PROMPTS=1`, `--quiet`).
- Standard input disconnection (`stdin=subprocess.DEVNULL`).
- Explicit execution timeouts (10 to 30 seconds).
- Complete redaction of sensitive subprocess buffers from error messages.

---

## 10. License & Security Contact

- **License**: Apache License 2.0. See [LICENSE](LICENSE) for details.
- **Security Contact**: For vulnerability reports or security inquiries, please contact `security@invoixy.com`.
