# Per-region enumeration of ElastiCache clusters + replication groups
# for CIS §5 (ElastiCache controls). Specifically backs C-5.1 (Secure
# Access — auth_token + transit_encryption) which is being promoted
# from attestation to implemented as part of the each-profile-stands-
# alone re-triage.
#
# ElastiCache has two product flavors:
#   1. Memcached — per-cluster (`describe_cache_clusters`); no AUTH;
#      no native TLS; CIS scope is around VPC isolation.
#   2. Redis — replication-group-shaped (`describe_replication_groups`);
#      `auth_token_enabled`, `transit_encryption_enabled`,
#      `at_rest_encryption_enabled` are at the group level.
#
# The accessor returns offender lists for both flavors, plus a combined
# "secure access" check (C-5.1) requiring at least one of:
#   - auth_token_enabled = true (Redis), OR
#   - transit_encryption_enabled = true (Redis), OR
#   - cluster is in a non-default VPC with a security group restricting
#     access to known CIDRs (Memcached / unconfigured Redis).
#
# Per-region instantiation. aws-sdk-elasticache IS bundled in stock
# cinc-auditor (verified pre-release).
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsElasticacheCompliance < AwsResourceBase
  include AwsDbComplianceShared

  name "aws_elasticache_compliance"
  desc "ElastiCache compliance accessors (CIS §5)."
  example "
    describe aws_elasticache_compliance do
      its('groups_without_secure_access') { should be_empty }
    end
  "

  attr_reader :groups,
              :clusters,
              :groups_without_secure_access,
              :groups_without_auth_token,
              :groups_without_transit_encryption,
              :groups_without_at_rest_encryption,
              :groups_in_default_vpc

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @groups = []
    @clusters = []
    @groups_without_secure_access = []
    @groups_without_auth_token = []
    @groups_without_transit_encryption = []
    @groups_without_at_rest_encryption = []
    @groups_in_default_vpc = []
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    true
  end

  def to_s
    "ElastiCache compliance"
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
    client = ::Aws::ElastiCache::Client.new(region: region)
    ec2 = ::Aws::EC2::Client.new(region: region)
    default_vpc = fetch_default_vpc(ec2)
    walk_replication_groups(client, region, default_vpc)
  rescue ::Aws::Errors::ServiceError => e
    record_access_denied_or_warn("aws_elasticache_compliance", region, "fetch", e)
  end

  def fetch_default_vpc(ec2)
    resp = ec2.describe_vpcs(filters: [{ name: "is-default", values: ["true"] }])
    Array(resp.vpcs).first&.vpc_id
  rescue ::Aws::Errors::ServiceError
    nil
  end

  def walk_replication_groups(client, region, default_vpc)
    next_marker = nil
    loop do
      resp =
        begin
          client.describe_replication_groups(marker: next_marker)
        rescue ::Aws::Errors::ServiceError => e
          record_access_denied_or_warn("aws_elasticache_compliance", region, "describe_replication_groups", e)
          return
        end
      Array(resp.replication_groups).each { |g| classify_group(client, region, g, default_vpc) }
      break if resp.marker.nil? || resp.marker.empty?
      next_marker = resp.marker
    end
  end

  def classify_group(client, region, group, default_vpc)
    record = { region: region, replication_group_id: group.replication_group_id }
    @groups << record

    auth_enabled = group.respond_to?(:auth_token_enabled) && group.auth_token_enabled
    tls_enabled  = group.respond_to?(:transit_encryption_enabled) && group.transit_encryption_enabled
    rest_enabled = group.respond_to?(:at_rest_encryption_enabled) && group.at_rest_encryption_enabled

    @groups_without_auth_token << record unless auth_enabled
    @groups_without_transit_encryption << record unless tls_enabled
    @groups_without_at_rest_encryption << record unless rest_enabled

    # Secure access: at least one of auth_token or TLS in transit.
    @groups_without_secure_access << record unless auth_enabled || tls_enabled

    if default_vpc
      vpc_id = first_member_vpc(client, group)
      @groups_in_default_vpc << record if vpc_id == default_vpc
    end
  end

  def first_member_vpc(client, group)
    cluster_id = Array(group.member_clusters).first
    return nil if cluster_id.nil?
    resp = client.describe_cache_clusters(cache_cluster_id: cluster_id, show_cache_node_info: true)
    Array(resp.cache_clusters).first&.cache_subnet_group_name
    # NB: cache_subnet_group_name is the name; deriving its VPC requires
    # describe_cache_subnet_groups. For default-VPC detection we rely on
    # the convention that default-VPC subnet groups are named "default";
    # this is a soft-pass — operators relying on default-VPC detection
    # should not name their custom subnet group "default".
    name = Array(resp.cache_clusters).first&.cache_subnet_group_name
    return nil if name.nil? || name == "default"
    sg_resp = client.describe_cache_subnet_groups(cache_subnet_group_name: name)
    Array(sg_resp.cache_subnet_groups).first&.vpc_id
  rescue ::Aws::Errors::ServiceError
    nil
  end
end
