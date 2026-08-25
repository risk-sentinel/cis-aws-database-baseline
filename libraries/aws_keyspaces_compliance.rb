# Per-region enumeration of Amazon Keyspaces (Cassandra-compatible)
# tables for CIS §8.1 / §8.2 / §8.3 / §8.4.
#
# §8.1 Keyspace Security — table-level encryption + access config.
# §8.2 Network Security — VPC endpoint for Keyspaces.
# §8.3 Data at Rest and in Transit — `encryption_specification.type ==
#      "CUSTOMER_MANAGED_KMS_KEY" or "AWS_OWNED_KMS_KEY"` (encrypted by
#      default; check confirms enabled).
# §8.4 Point-in-Time Recovery (PITR) — `point_in_time_recovery.status ==
#      "ENABLED"`.
#
# Defensive `aws-sdk-keyspaces` require — NOT bundled in upstream
# cinc-auditor 7.0.107. Use an extended auditor image that bundles the gem
# (your CI image-bake tracker) or controls fall back to connection_error skip.
#
# Memoization: the four §8 controls each instantiate this resource. Pre-
# memoization that meant 4× region walks AND 4× duplicate WARNs when
# the scanner role lacks `cassandra:Select` (the noisy case in the
# 2026-05-11 profile review). Resource state is now cached per
# (region-list) key in a module constant so the walk happens once.
#
# AccessDeniedException handling: previously each Aws::Errors::ServiceError
# was logged via Inspec::Log.warn and the resource walked on, leaving
# the empty-table accessors looking like vacuous PASSes. AccessDenied
# now sets connection_error explicitly so controls degrade to a clean
# Skip with rationale, per the Vendored_Resource_Gaps.md §5 precheck
# pattern.
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

module AwsKeyspacesComplianceCache
  STATE = {}
end

class AwsKeyspacesCompliance < AwsResourceBase
  include AwsDbComplianceShared

  name "aws_keyspaces_compliance"
  desc "Amazon Keyspaces compliance (CIS §8)."
  example "
    inv = aws_keyspaces_compliance(regions: input('scan_regions'))
    if inv.connection_error
      describe inv do; skip inv.connection_error; end
    else
      describe inv do
        its('regions_without_keyspaces_endpoint') { should be_empty }
        its('tables_without_encryption')          { should be_empty }
        its('tables_without_pitr')                { should be_empty }
      end
    end
  "

  attr_reader :tables,
              :regions_without_keyspaces_endpoint,
              :tables_without_encryption,
              :tables_without_pitr,
              :connection_error

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters

    cache_key = region_override.sort.join(",")
    cached = AwsKeyspacesComplianceCache::STATE[cache_key]
    if cached
      hydrate_from_cache(cached)
      return
    end

    @tables = []
    @regions_without_keyspaces_endpoint = []
    @tables_without_encryption = []
    @tables_without_pitr = []
    @connection_error = nil

    begin
      require "aws-sdk-keyspaces"
    rescue LoadError => e
      @connection_error = "aws-sdk-keyspaces not installed: #{e.message}. Use risksentinel/cinc-auditor extended image (your CI image-bake tracker) or attest separately."
      AwsKeyspacesComplianceCache::STATE[cache_key] = snapshot
      return
    end

    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
    AwsKeyspacesComplianceCache::STATE[cache_key] = snapshot
  end

  def exists?
    @connection_error.nil?
  end

  def to_s
    "Amazon Keyspaces compliance"
  end

  private

  def snapshot
    {
      tables: @tables,
      regions_without_keyspaces_endpoint: @regions_without_keyspaces_endpoint,
      tables_without_encryption: @tables_without_encryption,
      tables_without_pitr: @tables_without_pitr,
      connection_error: @connection_error,
    }
  end

  def hydrate_from_cache(cached)
    @tables = cached[:tables]
    @regions_without_keyspaces_endpoint = cached[:regions_without_keyspaces_endpoint]
    @tables_without_encryption = cached[:tables_without_encryption]
    @tables_without_pitr = cached[:tables_without_pitr]
    @connection_error = cached[:connection_error]
  end

  def fetch_default_regions
    regions = []
    catch_aws_errors do
      regions = @aws.compute_client.describe_regions.regions.map(&:region_name)
    end
    regions
  end

  def fetch_data
    @regions.each do |r|
      walk_region(r)
      break if @connection_error
    end
  end

  def walk_region(region)
    client = ::Aws::Keyspaces::Client.new(region: region)
    ec2    = ::Aws::EC2::Client.new(region: region)
    keyspace_names = list_keyspaces(client, region)
    return if @connection_error || keyspace_names.empty?
    check_vpc_endpoint(ec2, region)
    keyspace_names.each do |kspace|
      list_tables(client, region, kspace).each do |table_name|
        classify_table(client, region, kspace, table_name)
      end
    end
  rescue ::Aws::Errors::ServiceError => e
    record_access_denied_or_warn("aws_keyspaces_compliance", region, "fetch", e)
  end

  def list_keyspaces(client, region)
    names = []
    next_token = nil
    loop do
      resp =
        begin
          client.list_keyspaces(next_token: next_token)
        rescue ::Aws::Errors::ServiceError => e
          record_access_denied_or_warn("aws_keyspaces_compliance", region, "list_keyspaces", e)
          return names
        end
      names.concat(Array(resp.keyspaces).map(&:keyspace_name))
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
    names
  end

  def list_tables(client, region, keyspace)
    names = []
    next_token = nil
    loop do
      resp =
        begin
          client.list_tables(keyspace_name: keyspace, next_token: next_token)
        rescue ::Aws::Errors::ServiceError => e
          record_access_denied_or_warn("aws_keyspaces_compliance", region, "list_tables(#{keyspace})", e)
          return names
        end
      names.concat(Array(resp.tables).map(&:table_name))
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
    names
  end

  def check_vpc_endpoint(ec2, region)
    service_name = "com.amazonaws.#{region}.cassandra"
    resp =
      begin
        ec2.describe_vpc_endpoints(filters: [
          { name: "service-name", values: [service_name] },
          { name: "vpc-endpoint-state", values: ["available"] },
        ])
      rescue ::Aws::Errors::ServiceError
        @regions_without_keyspaces_endpoint << { region: region }
        return
      end
    if Array(resp.vpc_endpoints).empty?
      @regions_without_keyspaces_endpoint << { region: region }
    end
  end

  def classify_table(client, region, keyspace, table_name)
    desc =
      begin
        client.get_table(keyspace_name: keyspace, table_name: table_name)
      rescue ::Aws::Errors::ServiceError => e
        record_access_denied_or_warn("aws_keyspaces_compliance", region, "get_table(#{keyspace}/#{table_name})", e)
        return
      end
    record = { region: region, keyspace: keyspace, table: table_name, arn: desc.resource_arn }
    @tables << record
    enc = desc.encryption_specification
    encrypted = enc && %w[CUSTOMER_MANAGED_KMS_KEY AWS_OWNED_KMS_KEY].include?(enc.type.to_s)
    @tables_without_encryption << record unless encrypted
    pitr_status = desc.point_in_time_recovery&.status.to_s
    @tables_without_pitr << record unless pitr_status == "ENABLED"
  end

  # AccessDenied → @connection_error handled by AwsDbComplianceShared
  # (included at class top). When the scanner role lacks cassandra:*
  # IAM perms — the common case for accounts that don't use Keyspaces
  # — the §8 controls degrade to a clean Skip rather than reporting
  # vacuous PASSes off the empty-table accessors.
end
