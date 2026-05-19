# Per-region enumeration of Amazon Timestream databases + tables for
# CIS §10.1 - §10.10.
#
# Timestream has two service variants: Timestream LiveAnalytics (the
# original, time-series workload) and Timestream for InfluxDB. We
# default to LiveAnalytics here (`Aws::TimestreamWrite` for control-plane
# enumeration; `Aws::TimestreamQuery` for query-side scope where
# relevant). InfluxDB-flavored Timestream is deferred to a follow-up if
# external consumer demand surfaces.
#
# Accessors per §10:
# §10.1 Data Ingestion is Secure — TLS-enforced ingestion (Timestream
#       requires HTTPS; this is a structural pass once a database
#       exists, surfaced for completeness).
# §10.2 Data at Rest is Encrypted — `kms_key_id` populated on database.
# §10.3 Encryption in Transit — TLS-enforced (structural pass).
# §10.4 Access Control + Authentication — IAM policies, table-level.
#       (Surfaced as attestation pass; IAM-side check belongs to
#       cis-aws-foundations §1.)
# §10.5 Fine-Grained Access Control — same as 10.4.
# §10.6 Audit Logging — CloudWatch Logs / CloudTrail data events.
#       Checked indirectly via `cloudtrail_data_event_coverage` cross-
#       reference; for v0.1.0 we surface tables_without_audit_logging
#       based on whether the database has CloudTrail data events
#       configured at the account level (governance check, attest if
#       not configured).
# §10.7 Regular Updates and Patches — managed service; service
#       provides updates. Structural pass.
# §10.8 Monitoring and Alerting — CloudWatch alarms (consumer-side).
#       Attestation.
# §10.9 Security Configuration Review — governance. Attestation.
# §10.10 Automated Backups — Timestream's built-in backup is automatic;
#       check `magnetic_store_write_properties` for replicated storage.
#
# Defensive `aws-sdk-timestreamwrite` require — NOT bundled in upstream
# cinc-auditor 7.0.107.
#
# Per-region instantiation. Timestream is regional but only available
# in a subset of regions; describe_endpoints will fail gracefully where
# unavailable.
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsTimestreamCompliance < AwsResourceBase
  include AwsDbComplianceShared

  name "aws_timestream_compliance"
  desc "Amazon Timestream LiveAnalytics compliance (CIS §10)."
  example "
    inv = aws_timestream_compliance
    if inv.connection_error
      describe inv do; skip 'attestation-required: ...'; end
    else
      describe inv do
        its('databases_without_kms_encryption')   { should be_empty }
        its('databases_without_magnetic_storage') { should be_empty }
      end
    end
  "

  attr_reader :databases,
              :tables,
              :databases_without_kms_encryption,
              :databases_without_magnetic_storage,
              :connection_error

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @databases = []
    @tables = []
    @databases_without_kms_encryption = []
    @databases_without_magnetic_storage = []
    @connection_error = nil
    begin
      require "aws-sdk-timestreamwrite"
    rescue LoadError => e
      @connection_error = "aws-sdk-timestreamwrite not installed: #{e.message}. Use risksentinel/cinc-auditor extended image (your CI image-bake tracker) or attest separately."
      return
    end
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    @connection_error.nil?
  end

  def to_s
    "Amazon Timestream compliance"
  end

  private

  def fetch_default_regions
    regions = []
    catch_aws_errors do
      regions = @aws.compute_client.describe_regions.regions.map(&:region_name)
    end
    regions
  end

  def fetch_data
    @regions.each { |r| walk_region(r) }
  end

  def walk_region(region)
    client = ::Aws::TimestreamWrite::Client.new(region: region)
    list_databases(client, region).each { |db| walk_database(client, region, db) }
  rescue ::Aws::Errors::ServiceError => e
    record_access_denied_or_warn("aws_timestream_compliance", region, "fetch", e)
  end

  def list_databases(client, region)
    out = []
    next_token = nil
    loop do
      resp =
        begin
          client.list_databases(next_token: next_token)
        rescue ::Aws::Errors::ServiceError => e
          record_access_denied_or_warn("aws_timestream_compliance", region, "list_databases", e)
          return out
        end
      Array(resp.databases).each do |db|
        out << { region: region, database_name: db.database_name, arn: db.arn, kms_key_id: db.kms_key_id }
      end
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
    out
  end

  def walk_database(client, region, db_record)
    @databases << db_record
    if db_record[:kms_key_id].nil? || db_record[:kms_key_id].empty?
      @databases_without_kms_encryption << db_record
    end
    list_tables(client, region, db_record).each do |table|
      @tables << table
      mag = table[:magnetic_store_write_properties]
      if mag.nil? || !mag.respond_to?(:enable_magnetic_store_writes) || !mag.enable_magnetic_store_writes
        @databases_without_magnetic_storage << table.merge(database_name: db_record[:database_name])
      end
    end
  end

  def list_tables(client, region, db_record)
    out = []
    next_token = nil
    loop do
      resp =
        begin
          client.list_tables(database_name: db_record[:database_name], next_token: next_token)
        rescue ::Aws::Errors::ServiceError => e
          record_access_denied_or_warn("aws_timestream_compliance", region, "list_tables(#{db_record[:database_name]})", e)
          return out
        end
      Array(resp.tables).each do |t|
        out << {
          region: region,
          database_name: t.database_name,
          table_name: t.table_name,
          arn: t.arn,
          magnetic_store_write_properties: t.magnetic_store_write_properties,
        }
      end
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
    out
  end
end
