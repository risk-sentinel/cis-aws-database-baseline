# cis-aws-database-baseline

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=risk-sentinel_cis-aws-database-v2.0.0)](https://sonarcloud.io/summary/new_code?id=risk-sentinel_cis-aws-database-v2.0.0)

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

98 controls, grouped by service, following the CIS v2.0.0 numbering:

| Section | Service |
|---|---|
| 1–3 | RDS and Aurora — encryption, backups, public accessibility, minor-version upgrades, IAM auth, logging |
| 4 | DynamoDB — encryption, PITR, deletion protection |
| 5–6 | DocumentDB, Neptune — TLS, audit logs, encryption |
| 7 | Redshift — encryption, public access, logging, upgrades |
| 8–9 | ElastiCache, MemoryDB — transit and at-rest encryption, auth |
| 10 | Timestream, Keyspaces — encryption, backups, audit coverage |

---

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
      profile_name: cis-aws-database-v2.0.0
      profile_version: "0.1.0"
    secrets:
      AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}
```

**GitLab**

```yaml
include:
  - project: risk-sentinel/cis-aws-database-baseline
    file: /ci/gitlab/exec-evidence.yml
    inputs:
      target: my-account
      profile_name: cis-aws-database-v2.0.0
      profile_version: "0.1.0"
```

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

Schema authority: [dev-sec-ops-baseline#33](https://github.com/risk-sentinel/dev-sec-ops-baseline/issues/33).

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
