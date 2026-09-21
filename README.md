# cis-aws-database-baseline

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=risk-sentinel_cis-aws-database-baseline)](https://sonarcloud.io/summary/new_code?id=risk-sentinel_cis-aws-database-baseline)

InSpec / CINC Auditor profile validating AWS database services against the
**CIS AWS Database Services Benchmark v2.0.0** — 98 controls across RDS, Aurora,
DynamoDB, DocumentDB, Neptune, Redshift, ElastiCache, MemoryDB, Timestream and
Keyspaces.

Targets **AWS Commercial** and **AWS GovCloud (non-DoD)**. Per-control partition
applicability is in [`partition_applicability.yml`](partition_applicability.yml)
and encoded as `tag applicable_partitions:`.

---

## Quickstart

```bash
git clone https://github.com/risk-sentinel/cis-aws-database-baseline
cd cis-aws-database-baseline

cp inputs/example.yml inputs/mine.yml     # then edit — see Inputs below
cinc-auditor vendor . --overwrite

cinc-auditor exec . -t aws:// \
  --input-file inputs/mine.yml \
  --reporter cli json:results.json
```

**Pin `scan_regions` before your first run.** Left empty this profile enumerates
every region across ten database services, and a full-estate run can take well
over ten minutes — long enough to hit CI job timeouts. It is the single biggest
lever on runtime.

### Credentials

Standard AWS credential resolution. Read-only across the database surface:

```
rds:Describe*  dynamodb:Describe*  dynamodb:List*  docdb / neptune Describe*
redshift:Describe*  elasticache:Describe*  memorydb:Describe*
timestream:Describe*  timestream:List*   cassandra:Select
kms:DescribeKey  ec2:DescribeRegions  ec2:DescribeSecurityGroups
```

Services you do not use will report that they could not be reached rather than
passing — see below.

### What a first run looks like

Against a real account, scoped to one region:

**75 controls with results, 79 results — roughly 53 passed / 19 failed / 7 skipped.**

If you see far fewer, that is the signal to investigate. A run that assessed
nothing exits 0 and looks clean.

---

## Inputs

Fully documented in [`inputs/example.yml`](inputs/example.yml).

| Group | Inputs |
|---|---|
| **Required** | `aws_partition` |
| **Scoping** | `scan_regions`, `applicable_services`, `rds_engines` |
| **Thresholds** | `rds_backup_retention_minimum_days`, `approved_db_engines`, `db_security_review_cadence_days`, `db_security_review_last_date` |
| **Attestation** | three `*_attestation_reference` strings, the `*_base` URIs, four `*_evidence_uri` overrides |

**Scoping down is the normal first step.** This profile covers far more database
services than any one consumer runs. Naming your services in
`applicable_services` is faster than discovery and makes the denominator obvious.

**"Could not reach" is not "compliant".** When a service cannot be reached — an
account not entitled to it, or an API denied — the controls **skip with a
rationale naming the resource, operation and region**, rather than passing on an
empty collection. That distinction is deliberate: an empty result satisfies every
`should be_empty` assertion, so a service nobody could query would otherwise
report clean.

---

## Controls

98 controls, one section per service, following the CIS v2.0.0 numbering:

| Section | Service | Controls | Covers |
|---|---|---:|---|
| 2 | Aurora | 11 | security groups, IAM auth, delete protection, encryption at rest and in transit, least privilege, audit logging, password rotation, automatic backups |
| 3 | RDS | 14 | public accessibility, engine selection, VPC placement, backup and recovery, IAM auth, access control, periodic security-configuration review |
| 4 | DynamoDB | 9 | IAM, encryption at rest and in transit, fine-grained access control, VPC endpoints, backups, streams-driven compliance checking |
| 5 | ElastiCache | 13 | multi-AZ deployment, secure access, cluster mode, encryption at rest and in transit, automatic backups, automatic patching |
| 6 | MemoryDB | 7 | network security, authentication and access control, audit logging, encryption, automatic backups, monitoring and alerting |
| 7 | DocumentDB | 12 | network architecture, VPC security, delete protection, encryption at rest and in transit, backup window, audit logging, updates, security assessments |
| 8 | Keyspaces | 4 | network security, point-in-time recovery, encryption at rest and in transit, keyspace security |
| 9 | Neptune | 11 | network security, encryption at rest and in transit, delete protection, multi-AZ deployment, authentication and access control, audit logging |
| 10 | Timestream | 10 | secure ingestion, automated backups, encryption at rest and in transit, access control, fine-grained access control, audit logging, monitoring |
| 11 | Redshift | 7 | IAM, network access, encryption at rest and in transit, access control and authentication, monitoring and logging, backup and recovery |

**The numbering starts at 2 because the benchmark does.** CIS AWS Database
Services Benchmark v2.0.0 numbers its 98 recommendations 2.1 through 11.7; there
is no section 1 to implement and none is missing here. The per-section counts
above match the source one for one, and sum to 98.

This is a property of *this* benchmark rather than a CIS-wide convention — the
CIS AWS Storage Services Benchmark does have a section 1, and the Compute
benchmark skips several section numbers entirely. Section numbers are document
slots, and not every slot carries scored recommendations.

---

## Empty collections

Several controls loop over a collection and describe each member. If the account
holds none of that resource the loop never executes, so without care the control
registers no `describe` blocks and emits **zero results** — neither passed nor
Not Applicable, but *absent*. A control that asserts nothing while reporting
not-red is the failure this profile exists to catch, and it also breaks the
evidence pipeline: the HDF v3 schema requires at least one result per
requirement, so `hdf convert` refuses the whole document.

Those controls call `scoped_or_na` from
[`libraries/_scoped_collection.rb`](libraries/_scoped_collection.rb), which folds
emptiness into applicability and writes the `only_if` for them. An account
without the resource renders as **Not Applicable — a statement** — rather than as
silence.

The helper exists because expressing this inline cost every affected control the
same eight lines. Said once, each control keeps only what is specific to it:
which collection, why it might be out of scope, and what to assert.

---

## Running without GitHub access

Every release carries a `.tar.gz` asset, built and verified by
`.github/workflows/release-artifact.yml`.

It holds this profile **and its vendored dependencies**, so running it
contacts no remote at all — the shape for a consumer who can reach their own
accounts or hosts but cannot reach github.com.

Assets are attached to every release cut **after this workflow landed**; earlier
releases have none.

```bash
VERSION=<the release you want>

# once, from somewhere that CAN reach GitHub
curl -LO https://github.com/risk-sentinel/cis-aws-database-baseline/releases/download/$VERSION/cis-aws-database-v2.0.0-$VERSION.tar.gz

# then, on the isolated side
mkdir -p cis-aws-database-v2.0.0 && tar xzf cis-aws-database-v2.0.0-$VERSION.tar.gz -C cis-aws-database-v2.0.0
cd cis-aws-database-v2.0.0
cinc-auditor exec . -t aws:// --input-file inputs/example.yml
```

**Extract it, then run from inside the directory.** Executing the `.tar.gz` path
directly fails with `cannot load such file -- aws_backend`, because
`libraries/_aws_backend_bootstrap.rb` locates the vendored pack by globbing
`Dir.pwd` and an archive exec unpacks somewhere else.

The asset is verified before it is attached: the release job rejects an archive
that declares `depends:` but carries no `vendor/`, and it rejects one that will
not **load with the network switched off**. A tarball that exists is not a
tarball that works.

### From CI

Both templates take `profile_source`, defaulting to `git` — existing callers are
unaffected:

| value | behaviour |
| --- | --- |
| `git` | Vendor from the declared remotes. Needs to reach them. |
| `archive` | Unpack a release artifact. Contacts no remote. Requires `archive_path`. |

`archive` **never falls back to `git`.** An empty or missing `archive_path` fails
the job, as does an archive that declares dependencies but carries none. A
fallback would defeat the isolation the mode exists for *and* still report a
successful scan.

GitHub Actions:

```yaml
uses: risk-sentinel/cis-aws-database-baseline/.github/workflows/exec-evidence.yml@<version>
with:
  profile_source: archive
  archive_path: ./cis-aws-database-v2.0.0-<version>.tar.gz
```

GitLab:

```yaml
include:
  - project: <your-org>/cis-aws-database-baseline
    ref: <version>
    file: /ci/jobs/exec-evidence.yml
    inputs:
      profile_source: archive
      archive_path: ./cis-aws-database-v2.0.0-<version>.tar.gz
```

## Producing evidence

A `--reporter cli` run tells you the answer. It does not produce something an
assessor can trace back to what was assessed, when, by whom, or from which
scanner output. For that, use the CI templates — the whole pipeline, in YAML
with no helper scripts behind it:

**GitHub**

```yaml
jobs:
  evidence:
    uses: risk-sentinel/cis-aws-database-baseline/.github/workflows/exec-evidence.yml@main
    with:
      target: my-account
      boundary: my-boundary
      aws_region: us-east-1
      profile_name: cis-aws-database-v2.0.0
      profile_version: "0.1.0"
      inputs_file: inputs/mine.yml
    secrets:
      AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}
```

**GitLab**

```yaml
include:
  - project: risk-sentinel/cis-aws-database-baseline
    ref: v0.1.7
    file: /ci/jobs/exec-evidence.yml
    inputs:
      target: my-account
      boundary: my-boundary
      aws_region: us-east-1
      profile_name: cis-aws-database-v2.0.0
      profile_version: "0.1.0"
      inputs_file: inputs/mine.yml
```

`target`, `boundary`, `aws_region`, `profile_name` and `profile_version` are
required and have no defaults. A missing one is rejected before the job starts —
GitHub refuses the `workflow_call`, GitLab refuses the `include` — rather than
running against the wrong account or filing the results under the wrong label.
`inputs_file` defaults to `inputs/example.yml`, which runs with example values,
so set it to your own copy. See [docs/ci-templates.md](docs/ci-templates.md) for
the full contract, including which secrets are genuinely optional.

An `include:` brings YAML and nothing else, which is why the logic lives in the
YAML rather than in a script an including project would never receive. The
templates are carried in this repository on purpose: clone it or include it and
you have the entire pipeline, with nothing else to install.

### The order, and why it is that order

```
create passthrough -> execute -> convert (gate) -> apply -> label (gate)
                   -> validate (gate) -> display
```

The audit record is built **before** the scan, because that is when the honest
start time and the pipeline provenance are known. Only finish time, the artifact
digest and the outcome counts are added afterwards.

### Two artifacts

| artifact | shape | for |
|---|---|---|
| `results.final.json` | HDF v3 `baselines[]` | authoritative evidence — schema-validated, carries the audit record and typed target components, feeds `hdf convert --to oscal-sar` |
| `results-heimdall.json` | InSpec exec-json `profiles[]` | loading into Heimdall |

The Heimdall artifact is a **copy, not a conversion**. Tested against a live
Heimdall: every `profiles[]` variant loads, including the output of both
`--to hdf@1` and `--to hdf@2`; only the `baselines[]` v3 document is refused. So
the choice is fidelity, and every conversion path drops `resource_params` from
each result plus `depends` / `status` / `status_message` from the profile.
Copying what cinc-auditor already wrote loses nothing.

**Do not reach for `hdf convert --to hdf@2`.** The `hdf@N` namespace was
renumbered between hdf-libs 3.4.1 and 3.5.1 — on 3.4.1 it emits `baselines[]`,
on 3.5.1 `profiles[]` — so a pipeline pinned to it silently changes artifact
across an image bump. On 3.5.1, `@1` and `@2` are byte-identical.

### Three gates, each of which has failed silently in this estate

- `hdf convert` without `--no-validate`
- `hdf label` followed by `hdf label show | grep '^Component:'` — `label set`
  prints `Labels written` and writes a byte-identical file when the document has
  no components
- `hdf validate`

The exec step additionally fails the job on a missing or **zero-result**
artifact. A run that assessed nothing must not go green.

### The audit record

Written on every run — clean, failed, findings or none. Target, scan window,
scanner, profile and version, pipeline provenance, actor, converter, a sha256 of
the pre-conversion artifact, and outcome counts.

Two properties are deliberate: **absent is not empty** (an inapplicable field is
omitted, an undeterminable one is `null` with a reason), and the record **marks
which fields are corroborable** against systems the producer does not control.
An audit chain where every field is self-asserted is a story.

Schema authority: the shared evidence-store schema.

---

## Consuming this profile

Depend on it rather than forking, so you get fixes:

```yaml
depends:
  - name: cis-aws-database-v2.0.0
    git: https://github.com/risk-sentinel/cis-aws-database-baseline.git
    tag: v0.1.5
```

Then `include_controls 'cis-aws-database-v2.0.0'` and supply your own inputs. Input overrides
reach the depended profile's controls, so your values win without editing
anything here.

## Contributing

Control logic changes belong here. `cinc-auditor check` only *loads* a profile —
it will not catch a resource that returns empty because an API call failed.
Anything touching `libraries/` needs a real `exec` against a real target before
it is trusted.

## License

Apache-2.0. See [LICENSE](LICENSE).
