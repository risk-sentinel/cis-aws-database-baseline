# Per-region enumeration of DynamoDB tables for CIS §4.5 / §4.8 / §4.9.
#
# §4.5 — VPC endpoints for DynamoDB. We check via EC2 describe_vpc_endpoints
# in each region for `com.amazonaws.<region>.dynamodb` Available endpoints.
# Per CIS guidance, tables in private VPCs should access DynamoDB through
# the gateway endpoint to avoid public-internet egress.
#
# §4.8 — `deletion_protection_enabled` field on each table.
#
# §4.9 — Point-in-Time Recovery enabled (continuous-backup) OR an AWS
# Backup plan covering the table. We check `describe_continuous_backups`
# `point_in_time_recovery_status == "ENABLED"`.
#
# Per-region instantiation. aws-sdk-dynamodb IS bundled in stock cinc-auditor.
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsDynamodbCompliance < AwsResourceBase
  include AwsDbComplianceShared

  name "aws_dynamodb_compliance"
  desc "DynamoDB compliance accessors (CIS §4.5 / §4.8 / §4.9)."
  example "
    inv = aws_dynamodb_compliance
    describe inv do
      its('regions_without_dynamodb_endpoint')   { should be_empty }
      its('tables_without_deletion_protection')  { should be_empty }
      its('tables_without_pitr')                 { should be_empty }
    end
  "

  attr_reader :tables,
              :regions_without_dynamodb_endpoint,
              :tables_without_deletion_protection,
              :tables_without_pitr,
              :tables_without_streams,
              :tables_without_resource_policy

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @tables = []
    @regions_without_dynamodb_endpoint = []
    @tables_without_deletion_protection = []
    @tables_without_pitr = []
    @tables_without_streams = []
    @tables_without_resource_policy = []
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    true
  end

  def to_s
    "DynamoDB compliance"
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
    ddb = ::Aws::DynamoDB::Client.new(region: region)
    ec2 = ::Aws::EC2::Client.new(region: region)
    table_names = list_tables(ddb, region)
    return if table_names.empty?
    check_vpc_endpoint(ec2, region)
    table_names.each { |name| classify_table(ddb, region, name) }
  rescue ::Aws::Errors::ServiceError => e
    record_access_denied_or_warn("aws_dynamodb_compliance", region, "fetch", e)
  end

  def list_tables(client, region)
    names = []
    last_name = nil
    loop do
      resp =
        begin
          client.list_tables(exclusive_start_table_name: last_name)
        rescue ::Aws::Errors::ServiceError => e
          record_access_denied_or_warn("aws_dynamodb_compliance", region, "list_tables", e)
          return names
        end
      names.concat(Array(resp.table_names))
      break if resp.last_evaluated_table_name.nil? || resp.last_evaluated_table_name.empty?
      last_name = resp.last_evaluated_table_name
    end
    names
  end

  def check_vpc_endpoint(ec2, region)
    service_name = "com.amazonaws.#{region}.dynamodb"
    resp =
      begin
        ec2.describe_vpc_endpoints(filters: [
          { name: "service-name", values: [service_name] },
          { name: "vpc-endpoint-state", values: ["available"] },
        ])
      rescue ::Aws::Errors::ServiceError
        @regions_without_dynamodb_endpoint << { region: region }
        return
      end
    if Array(resp.vpc_endpoints).empty?
      @regions_without_dynamodb_endpoint << { region: region }
    end
  end

  def classify_table(client, region, table_name)
    desc =
      begin
        client.describe_table(table_name: table_name).table
      rescue ::Aws::Errors::ServiceError => e
        record_access_denied_or_warn("aws_dynamodb_compliance", region, "describe_table(#{table_name})", e)
        return
      end
    record = { region: region, table_name: table_name, table_arn: desc.table_arn }
    @tables << record
    if desc.respond_to?(:deletion_protection_enabled) && !desc.deletion_protection_enabled
      @tables_without_deletion_protection << record
    end
    pitr =
      begin
        client.describe_continuous_backups(table_name: table_name).continuous_backups_description
      rescue ::Aws::Errors::ServiceError
        nil
      end
    pitr_enabled = pitr&.point_in_time_recovery_description&.point_in_time_recovery_status.to_s == "ENABLED"
    @tables_without_pitr << record unless pitr_enabled

    # C-4.6: Streams enabled (for compliance-pipeline integrations).
    streams_enabled = desc.respond_to?(:stream_specification) &&
                      desc.stream_specification &&
                      desc.stream_specification.stream_enabled
    @tables_without_streams << record unless streams_enabled

    # C-4.1 / C-4.2: presence of a resource-based policy (least-priv +
    # fine-grained access). Tables without an explicit resource policy
    # default to identity-policy-only access — acceptable when account-
    # level IAM is well-scoped, but the explicit-policy posture is the
    # CIS-aligned bar.
    has_policy =
      begin
        client.get_resource_policy(resource_arn: desc.table_arn)
        true
      rescue ::Aws::DynamoDB::Errors::PolicyNotFoundException, ::Aws::DynamoDB::Errors::ResourceNotFoundException
        false
      rescue ::Aws::Errors::ServiceError
        false
      end
    @tables_without_resource_policy << record unless has_policy
  end
end
