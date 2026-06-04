# cis-aws-database — verification coverage matrix

Phase C (verification-rigor sweep). Principle: **verify the technical state
wherever the platform can answer it; never accept a human attestation as proof
of a checkable fact.**

Most of this profile's verification was already established in the pre-release
pass (PR #103) and the #154 conversion (PR #160): 90 `implemented` (direct
RDS/Redshift/DynamoDB/ElastiCache/MemoryDB/Timestream/Keyspaces API assertions)
+ 4 `inherited` → `:leveraged` evidence. This matrix documents why the residual
attestations are genuinely unverifiable (so an auditor can't be misled by a doc).

| Control | Disposition | Why not verified |
|---|---|---|
| 90 controls | `implemented` | Direct API assertion of the actual state |
| C-10.1 / C-10.3 / C-10.7 / C-4.4 | `inherited` → `:leveraged` | AWS service-default (TLS/patching); AWS authorization freshness-checked (#160) |
| **C-7.11** DocumentDB security assessment | attest (justified) | Bi-annual pen-test / security-assessment is an off-platform activity; no API exposes "an assessment was performed." Freshness floor on the record. |
| **C-10.4** Timestream access control | attest (cross-domain) | Per-table **IAM policy** granularity — *which principals may access which tables* — is an account-wide IAM-policy-graph analysis (a cis-aws-foundations §1 concern), not a Timestream-API fact. |
| **C-10.5** Timestream fine-grained access | attest (cross-domain) | Same — IAM-policy-condition analysis, not exposed by the Timestream API. |
| **C-10.6** Timestream audit logging | attest (verifiable — cross-domain, deferred) | **Verifiable** via CloudTrail **data-event** coverage for Timestream — but that's the cis-cloudtrail profile's mechanism (C-CT-3.x), not a Timestream-API fact. Timestream is also out of SPARC's runtime scope. Cross-referenced; net-new in-profile resource not shipped unvalidated. |

## Why no in-profile automation added in Phase C
The residual attestations are either off-platform governance (C-7.11) or
cross-domain IAM/CloudTrail concerns (C-10.4/10.5/10.6) better verified by the
IAM (foundations §1) and CloudTrail profiles. Each retains a `document_attestation`
freshness floor. The trust boundary is now explicit and auditable.
