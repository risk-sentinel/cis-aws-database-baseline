# Per-region enumeration of MemoryDB clusters for CIS §6.1 / §6.2 /
# §6.3 / §6.4 / §6.7.
#
# §6.1 Network Security — VPC subnet group + security groups.
# §6.2 Data at Rest + in Transit — `at_rest_encryption_enabled` + `tls_enabled`.
# §6.3 Authentication — ACL config (must be non-default `open-access`).
# §6.4 Audit Logging — `engine_log_group_arn` populated.
# §6.7 Automatic Backups — `snapshot_retention_limit > 0`.
#
# Defensive `aws-sdk-memorydb` require — NOT bundled in upstream
# cinc-auditor 7.0.107. Use risksentinel/cinc-auditor extended image
# (your CI image-bake tracker) or controls fall back to attestation rationale.
#
# Per-region instantiation.
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsMemorydbCompliance < AwsResourceBase
  include AwsDbComplianceShared

  name "aws_memorydb_compliance"
  desc "MemoryDB cluster compliance (CIS §6.1-§6.4 + §6.7)."
  example "
    inv = aws_memorydb_compliance
    if inv.connection_error
      describe inv do; skip 'attestation-required: ...'; end
    else
      describe inv do
        its('clusters_in_default_vpc')              { should be_empty }
        its('clusters_without_at_rest_encryption')  { should be_empty }
        its('clusters_without_tls')                 { should be_empty }
        its('clusters_with_open_access_acl')        { should be_empty }
        its('clusters_without_audit_logging')       { should be_empty }
        its('clusters_without_backups')             { should be_empty }
      end
    end
  "

  attr_reader :clusters,
              :clusters_in_default_vpc,
              :clusters_without_at_rest_encryption,
              :clusters_without_tls,
              :clusters_with_open_access_acl,
              :clusters_without_audit_logging,
              :clusters_without_backups,
              :connection_error

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @clusters = []
    @clusters_in_default_vpc = []
    @clusters_without_at_rest_encryption = []
    @clusters_without_tls = []
    @clusters_with_open_access_acl = []
    @clusters_without_audit_logging = []
    @clusters_without_backups = []
    @connection_error = nil
    begin
      require "aws-sdk-memorydb"
    rescue LoadError => e
      @connection_error = "aws-sdk-memorydb not installed: #{e.message}. Use risksentinel/cinc-auditor extended image (your CI image-bake tracker) or attest separately."
      return
    end
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    @connection_error.nil?
  end

  def to_s
    "MemoryDB compliance"
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
    client = ::Aws::MemoryDB::Client.new(region: region)
    ec2 = ::Aws::EC2::Client.new(region: region)
    default_vpc = fetch_default_vpc(ec2)
    next_token = nil
    loop do
      resp =
        begin
          client.describe_clusters(next_token: next_token)
        rescue ::Aws::Errors::ServiceError => e
          record_access_denied_or_warn("aws_memorydb_compliance", region, "describe_clusters", e)
          return
        end
      Array(resp.clusters).each { |c| classify(client, region, c, default_vpc) }
      break if resp.next_token.nil? || resp.next_token.empty?
      next_token = resp.next_token
    end
  end

  def fetch_default_vpc(ec2)
    resp = ec2.describe_vpcs(filters: [{ name: "is-default", values: ["true"] }])
    Array(resp.vpcs).first&.vpc_id
  rescue ::Aws::Errors::ServiceError
    nil
  end

  def classify(client, region, cluster, default_vpc)
    record = { region: region, name: cluster.name, status: cluster.status }
    @clusters << record
    @clusters_without_at_rest_encryption << record unless cluster.at_rest_encryption_enabled
    @clusters_without_tls << record unless cluster.tls_enabled
    @clusters_without_audit_logging << record unless engine_logs_configured?(cluster)
    @clusters_without_backups << record if cluster.snapshot_retention_limit.to_i <= 0
    acl_name = cluster.acl_name.to_s
    @clusters_with_open_access_acl << record if acl_name == "open-access" || acl_name.empty?
    if default_vpc
      vpc_id = subnet_group_vpc(client, cluster.subnet_group_name)
      @clusters_in_default_vpc << record if vpc_id == default_vpc
    end
  end

  def engine_logs_configured?(cluster)
    return false unless cluster.respond_to?(:log_delivery_configurations)
    Array(cluster.log_delivery_configurations).any? do |c|
      c.log_type.to_s == "engine-log" && c.status.to_s == "active"
    end
  end

  def subnet_group_vpc(client, subnet_group_name)
    return nil if subnet_group_name.to_s.empty?
    resp = client.describe_subnet_groups(subnet_group_name: subnet_group_name)
    Array(resp.subnet_groups).first&.vpc_id
  rescue ::Aws::Errors::ServiceError
    nil
  end
end
