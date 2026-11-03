# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | yes       |
| < 1.0   | no        |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems.

Email `security@quantumshield.example` with:

* a description of the issue and its impact,
* steps to reproduce or a proof of concept,
* the commit or release you tested against.

You will receive an acknowledgement within 2 business days and a remediation plan within 7 days.
We follow coordinated disclosure with a default 90-day embargo, shortened when a fix ships earlier.

## Scope

In scope: everything in this repository, including the KMS, relay, gateway configuration, SDKs,
web application, scanner, Helm chart, Terraform and CI workflows.

Out of scope: the upstream implementations we depend on (PQClean, liboqs, OpenSSL, noble). Report
those to their maintainers; we will track and ship the fix.

## Cryptographic design

The algorithms, parameters and protocol constructions are described in `ARCHITECTURE.md` §5 and §9.
The threats considered and their mitigations are in `THREAT_MODEL.md`. Known limitations are listed
in `THREAT_MODEL.md` §5 (residual risks).

## Hardening checklist for operators

* Run the KMS only behind mTLS with certificates from your internal CA (`QSHIELD_KMS_CLIENT_CA`).
* Use Vault Transit or AWS KMS as the KEK provider in production; `local-shamir` is for
  development and disaster recovery.
* Rotate the API key pepper (`QSHIELD_API_KEY_PEPPER`) only via the documented runbook procedure,
  which re-hashes stored keys.
* Enable the `strict` gateway profile when all clients are PQ-capable.
* Keep the algorithm registry under code review; a status change is a security-relevant change.
* Review `GET /v1/audit/verify` output from your monitoring at least daily.

## Security testing in CI

* Known-Answer Tests against NIST ACVP vectors (ML-KEM, ML-DSA, SLH-DSA).
* Property tests (round trips, tampering, wrong keys) across all parameter sets.
* Protocol tests for PQXDH and the ratchet (forward secrecy, post-compromise security, replay,
  out-of-order, prekey exhaustion).
* dudect-style timing tests for decapsulation and signing.
* Leak-scan test that searches every output for private key bytes.
* Semgrep (OWASP rulesets), cargo-audit, clippy with `-D warnings`, Bandit, pip-audit, npm audit,
  Trivy, Syft SBOM and cosign signing. CI fails on any HIGH or CRITICAL finding.
