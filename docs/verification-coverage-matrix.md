# cis-aws-database — verification coverage matrix

Phase C (verification-rigor sweep). Principle: **verify the technical state
wherever the platform can answer it; never accept a human attestation as proof
of a checkable fact.**

Most of this profile's verification was already established in the pre-release
pass and the conversion: 90 `implemented` (direct
RDS/Redshift/DynamoDB/ElastiCache/MemoryDB/Timestream/Keyspaces API assertions)
+ 4 `inherited` → `:leveraged` evidence. This matrix documents why the residual
attestations are genuinely unverifiable (so an auditor can't be misled by a doc).

| Control | Disposition | Why not verified |
|---|---|---|
| 90 controls | `implemented` | Direct API assertion of the actual state |
| C-10.1 / C-10.3 / C-10.7 / C-4.4 | `inherited` → `:leveraged` | AWS service-default (TLS/patching); AWS authorization freshness-checked |
| **C-7.11** DocumentDB security assessment | attest (justified) | Bi-annual pen-test / security-assessment is an off-platform activity; no API exposes "an assessment was performed." Freshness floor on the record. |
| **C-10.4** Timestream access control | **VERIFY (in-profile)** | `aws_timestream_access_iam` scans customer-managed policies for broad `timestream:*` on `Resource:*` (least-privilege). Built in-profile per each_profile_stands_alone, NOT deferred to foundations §1. exec_validated:false. |
| **C-10.5** Timestream fine-grained access | **VERIFY (in-profile)** | `aws_timestream_access_iam.unscoped_resource_policies` — FGAC requires per-database/table resource scoping (no `Resource:*`). exec_validated:false. |
| **C-10.6** Timestream audit logging | **VERIFY (in-profile)** | `aws_timestream_audit_coverage` checks every CloudTrail trail's event selectors for an `AWS::Timestream` data-resource. Built in-profile per each_profile_stands_alone (NOT deferred to cis-cloudtrail). exec_validated:false. |

## Residual attestation — why
- **C-7.11** DocumentDB security assessment — bi-annual pen-test is an off-platform
  activity; no API exposes "an assessment was performed." Freshness floor on the record.

C-10.4/10.5/10.6 (Timestream IAM + audit) are now VERIFIED in-profile (above) per
each_profile_stands_alone — no longer deferred to foundations/cloudtrail. The trust
boundary is explicit and auditable.
