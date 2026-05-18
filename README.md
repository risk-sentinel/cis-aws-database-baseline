# AWS Database Services CIS Baseline

InSpec / CINC Auditor profile validating an AWS account against **CIS AWS Database Services Benchmark v2.0.0**.

## Scope

- **AWS Commercial** (`aws_partition=aws`) — primary target.
- **AWS GovCloud non-DoD** (`aws_partition=aws-us-gov`) — primary target.
- Azure and other cloud providers — out of scope.

Per-control partition applicability lives in
`partition_applicability.yml` and is mirrored on each control via
`tag applicable_partitions: [...]`. Controls not applicable to the
running partition skip (impact 0.0) via `only_if`; they do not fail.

## Running Locally

Prerequisites: Docker. Vendor once to pull the `inspec-aws` resource pack:

```bash
docker pull risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1

docker run --rm -v "$PWD:/src" risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 \
  vendor /src/profiles/cis-aws-database --overwrite
```

Execute against AWS Commercial:

```bash
docker run --rm \
  -v "$PWD:/src" \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_DEFAULT_REGION=us-east-1 \
  risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 exec /src/profiles/cis-aws-database \
  --input aws_partition=aws \
  --reporter cli json:/src/hdf.json
```

For GovCloud, switch the partition input and region:

```bash
docker run --rm \
  -v "$PWD:/src" \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_DEFAULT_REGION=us-gov-west-1 \
  risksentinel/cinc-auditor@sha256:e483ae61a60ddcb9e6e9d782e79dbdeec87a3fe6271e59e96c332fc1d159d6f1 exec /src/profiles/cis-aws-database \
  --input aws_partition=aws-us-gov \
  --reporter cli json:/src/hdf.json
```

## Portability

This profile runs unchanged across AWS partitions (Commercial + GovCloud non-DoD, documentation-backed where not testable) and across consumers with different database footprints. Consumers never fork the profile — they set declared inputs in their own `inputs.yml` or via `--input-file` / `--input`.

### Inputs

| Input | Default | When to override |
| - | - | - |
| `aws_partition` | `aws` | Set to `aws-us-gov` when scanning GovCloud non-DoD. Controls the `only_if` partition guard on each control. |
| `applicable_services` | `[]` (all applicable) | Set to an explicit list when the target account uses only a subset of database services. Reduces false-negative coverage by auto-skipping sections for services the consumer doesn't operate. |
| `rds_engines` | `[]` (all engines) | Sections 2 + 3 only. Set to an explicit list of RDS engine identifiers (`aurora-postgresql`, `aurora-mysql`, `postgres`, `mysql`, `mariadb`, `oracle-ee`, `sqlserver-*`) to scope iteration to the engines you run. Empty evaluates every visible RDS instance. Defence-in-depth filter — not a replacement for per-engine CIS profiles (e.g., `cis-postgresql`) where postgresql.conf / parameter-group level controls live. |
| `rds_backup_retention_minimum_days` | `7` | Minimum acceptable `backup_retention_period` for CIS 2.8. CIS literal is "> 0"; default matches FedRAMP / enterprise baseline. Raise for stricter retention policies. |

### Service scope — `applicable_services`

CIS AWS Database Services v2.0 divides its controls by service, and so does this profile:

| CIS section | Service | `applicable_services` value |
| - | - | - |
| 2 + 3 | RDS (covers Aurora — Aurora is an RDS engine) | `rds` |
| 4 | DynamoDB | `dynamodb` |
| 5 | ElastiCache | `elasticache` |
| 6 | MemoryDB | `memorydb` |
| 7 | DocumentDB | `documentdb` |
| 8 | Keyspaces | `keyspaces` |
| 9 | Neptune | `neptune` |
| 10 | Timestream | `timestream` |
| 11 | Redshift | `redshift` |

An empty `applicable_services` (the profile default) runs every section — the conservative choice for a consumer that may use any AWS database service. A non-empty list skips sections for services not in the list; the skip message on each out-of-scope control reads `"<SERVICE> not in applicable_services; out of scope for this scan"`.

Stacks with `aws_partition` — both guards must pass for a control to run. Example control logic:

```ruby
only_if("Not applicable to AWS partition #{input('aws_partition')}") do
  ['aws', 'aws-us-gov'].include?(input('aws_partition'))
end

only_if('DYNAMODB not in applicable_services; out of scope for this scan') do
  s = Array(input('applicable_services'))
  s.empty? || s.include?('dynamodb')
end
```

### Example: consumer running RDS / Aurora-PostgreSQL only

```yaml
aws_partition: aws
applicable_services:
  - rds
rds_engines:
  - aurora-postgresql
```

### Example: consumer with multiple services

```yaml
aws_partition: aws
applicable_services:
  - rds
  - dynamodb
  - elasticache
rds_engines:
  - aurora-postgresql
  - aurora-mysql
  - postgres
```

### Example: consumer running all engines (no filter)

```yaml
aws_partition: aws
applicable_services:
  - rds
# rds_engines omitted — defaults to empty; evaluates every visible
# RDS instance regardless of engine.
```

### Default posture

A consumer that leaves `applicable_services` unset gets every section's checks. That maximises coverage at the cost of more skips when vendored resources don't cover a given service — follow-up issues exist for each service once a real consumer adopts it.

## NIST 800-53 Tagging

Every control carries `tag nist: [...]` resolved at scaffold time from
the XCCDF's DISA CCI identifiers via Heimdall's
`CciNistMappingData.ts`. Provenance chain:

```
XCCDF <ident system="http://cyber.mil/cci">CCI-XXXXXX</ident>
    ↓ (lookup in heimdall2/libs/hdf-converters/src/mappings/CciNistMappingData.ts)
NIST 800-53 control (e.g. "AC-2 (3)")
    ↓ (emitted by tools/xccdf_to_inspec/scaffold.py)
tag nist: ['AC-2 (3)']
```

The scaffolder **fails loudly** if any rule has a CCI that is not
present in the map — we never ship controls with CCI-only tags.

## Regenerating From XCCDF

```bash
python3 tools/xccdf_to_inspec/scaffold.py \
  --xccdf benchmarks/xccdf/cis_aws_database_services_benchmark_v200.xml \
  --cci-map /path/to/heimdall2/libs/hdf-converters/src/mappings/CciNistMappingData.ts \
  --output profiles/cis-aws-database \
  --profile-name cis-aws-database \
  --profile-title "AWS Database Services CIS Baseline" \
  --supports-platform aws
```

Use `--only <cis-number>` to regenerate a single control.

## Status

All 98 controls filled (sub-task 1b, issue #6) and all `planned` controls closed via the v0.1.0 release-prep sweep (#79 Phase B3 + B3+). Each control carries a `tag implementation_status:` mapped to OSCAL's native vocabulary. Per the each-profile-stands-alone principle, the depth-pass (Phase B3+) promoted 21 of the original 31 alternatives to implemented or inherited — each profile must produce its own coverage rather than cross-reference another profile's checks.

### Coverage distribution

| Type | `implementation_status` | Count | Meaning |
| - | - | - | - |
| **Automated** | `implemented` | 84 | Real describe against vendored or local resource; produces pass/fail against the target account. |
| **Attestation** | `alternative` | 10 | Only governance-cadence controls remain (annual / quarterly security-review + security-assessment cadences whose evidence is human-attested) plus 3 Timestream IAM/audit cross-resource checks. Each surfaces a `<topic>_attestation_reference` input for the consumer to point at their review-doc location; the skip message embeds the reference verbatim. |
| **Inherited** | `inherited` | 4 | AWS shared-responsibility model: Timestream service-default behaviors (TLS-in-transit, managed updates) and DynamoDB endpoint TLS enforcement — inherently satisfied by the AWS service. |
| **Pending-resource** | `planned` | 0 | — |

The 36-control jump from 28 → 64 implemented covers six new custom libraries spanning seven engines:

- `aws_rds_cluster_compliance` — multi-engine RDS-API-shape library covering RDS / Aurora (§2 + §3) + DocumentDB (§7) + Neptune (§9). 23 control wins via one shared library.
- `aws_dynamodb_compliance` — DynamoDB §4 (3 controls).
- `aws_redshift_compliance` — Redshift §11 (2 controls).
- `aws_memorydb_compliance` — MemoryDB §6 (5 implemented + 2 attestation).
- `aws_keyspaces_compliance` — Keyspaces §8 (4 controls).
- `aws_timestream_compliance` — Timestream §10 (2 implemented + 5 attestation + 3 inherited).

The `aws-sdk-memorydb` / `aws-sdk-keyspaces` / `aws-sdk-timestreamwrite` gems are NOT bundled in upstream `cincproject/auditor`. Consumers run against the **Risk Sentinel extended cinc-auditor image** ([sparc-iac#229](https://github.com/risk-sentinel/sparc-iac/issues/229)). With stock cinc-auditor, the affected controls fall back to attestation rationale via `connection_error` per [`docs/dev/Vendored_Resource_Gaps.md` §5](../../docs/dev/Vendored_Resource_Gaps.md#5-connection-precheck-describe-for-network-crossing-resources). DocumentDB / Neptune use the bundled `aws-sdk-rds` (engine: docdb / neptune) — no extension image needed for those.

### Per-section breakdown

| Section | Service | Controls | Automated | Attestation | Inherited | Planned | `exec_validated` |
| - | - | - | - | - | - | - | - |
| 2 | RDS / Aurora | 11 | 8 | 3 | 0 | 0 | *pending live exec validation* |
| 3 | RDS / Aurora | 14 | 10 | 4 | 0 | 0 | *pending live exec validation* |
| 4 | DynamoDB | 9 | 4 | 5 | 0 | 0 | false |
| 5 | ElastiCache | 13 | 9 | 4 | 0 | 0 | false |
| 6 | MemoryDB | 7 | 5 | 2 | 0 | 0 | false |
| 7 | DocumentDB | 12 | 10 | 2 | 0 | 0 | false |
| 8 | Keyspaces | 4 | 4 | 0 | 0 | 0 | false |
| 9 | Neptune | 11 | 8 | 3 | 0 | 0 | false |
| 10 | Timestream | 10 | 2 | 5 | 3 | 0 | false |
| 11 | Redshift | 7 | 4 | 3 | 0 | 0 | false |

### `exec_validated` tag semantics

A control tagged `tag exec_validated: false` has a syntactically-valid describe body but has **not** been run against live resources. Consumers running RDS-only (e.g., `applicable_services: [rds]`) will validate sections 2 + 3 on the first live `cinc-auditor exec`. Sections 4–11 controls carry `exec_validated: false` and stay untested — a consumer enabling any of those services via `applicable_services` is expected to validate before relying on pass/fail output.

See the top-level `README.md` for overall repo state and the sub-issue tracker for per-profile progress.
