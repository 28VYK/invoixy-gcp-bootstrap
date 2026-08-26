# Changelog

All notable changes to `invoixy-gcp-bootstrap` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-26

### Added
- Interactive terminal assistant (`invoixy-gcp-bootstrap`) for guided review authorization, status inspection, and revocation.
- Scriptable CLI subcommands (`plan`, `authorize`, `status`, `revoke`) with `--json`, `--yes`, and `--dry-run` support.
- Cryptographically verified, frozen 42-permission custom role contract (`InvoixySecurityAuditorV1`).
- Ephemeral Google Cloud IAM conditional policy binding (`request.time < timestamp(...)`) with default 8-hour TTL (maximum 24 hours).
- Fail-closed role verification preventing mutation if custom role definition drifts or permissions deviate from contract.
- Status inspection before revocation with safe summary display and cancellation support.
- Zero-dependency client-side architecture using standard Python library and local `gcloud` CLI.
- Public trust model: no customer-provided Google service-account JSON keys and short-lived scanner access via X.509 Workload Identity Federation.
