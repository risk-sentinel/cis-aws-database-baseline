# Per-region enumeration of RDS-API-managed clusters + instances (RDS,
# Aurora, DocumentDB, Neptune) with composite compliance accessors used
# across §2 RDS, §3 RDS, §7 DocumentDB, §9 Neptune.
#
# Why one library across four "engines": the RDS API surface
# (`describe_db_clusters`, `describe_db_instances`,
# `describe_db_cluster_parameters`) covers all four. DocumentDB and
# Neptune are both RDS-API-managed at the control plane (engine values
# `docdb` / `neptune`); their per-engine SDKs (aws-sdk-docdb,
# aws-sdk-neptune) only matter for engine-specific operations CIS
# doesn't check. Building one library against `Aws::RDS::Client` with
# engine-aware filtering keeps the code surface small and the cross-
# engine consistency obvious.
#
# Engine filtering: `engines:` kwarg accepts an array of engine prefix
# patterns (e.g., `["aurora-postgresql"]`, `["docdb"]`,
# `["aurora-mysql", "aurora-postgresql"]`, `["postgres", "mysql"]`).
# Empty / nil = no filter (every visible cluster + instance evaluated).
# This matches the existing `rds_engines` input.
#
# Each accessor returns a `violations` list of {region, identifier, ...}.
# The control body checks `inv.<accessor>.empty?`.
#
# Per-region instantiation (consistent with the rest of the codebase).
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsRdsClusterCompliance < AwsResourceBase
  include AwsDbComplianceShared

  name "aws_rds_cluster_compliance"
  desc "Multi-engine RDS-API compliance accessors (RDS / Aurora / DocumentDB / Neptune)."
  example "
    inv = aws_rds_cluster_compliance(engines: ['docdb'])
    describe inv do
      its('clusters_without_storage_encrypted')      { should be_empty }
      its('clusters_without_in_transit_encryption')  { should be_empty }
      its('clusters_without_deletion_protection')    { should be_empty }
      its('clusters_without_backup_retention')       { should be_empty }
      its('clusters_without_audit_logging')          { should be_empty }
      its('clusters_without_auto_minor_upgrade')     { should be_empty }
      its('clusters_without_iam_authentication')     { should be_empty }
      its('clusters_in_default_vpc')                 { should be_empty }
      its('clusters_with_open_security_groups')      { should be_empty }
      its('clusters_without_backup_window')          { should be_empty }
    end
  "

  ENGINE_TLS_PARAM = {
    "postgres"           => "rds.force_ssl",
    "aurora-postgresql"  => "rds.force_ssl",
    "mysql"              => "require_secure_transport",
    "mariadb"            => "require_secure_transport",
    "aurora-mysql"       => "require_secure_transport",
    "docdb"              => "tls",
    "neptune"            => nil,
  }.freeze

  attr_reader :clusters,
              :clusters_without_storage_encrypted,
              :clusters_without_in_transit_encryption,
              :clusters_without_deletion_protection,
              :clusters_without_backup_retention,
              :clusters_without_audit_logging,
              :clusters_without_auto_minor_upgrade,
              :clusters_without_iam_authentication,
              :clusters_in_default_vpc,
              :clusters_with_open_security_groups,
              :clusters_without_backup_window,
              :clusters_without_multi_az,
              :clusters_with_unapproved_engine,
              :clusters_without_iam_role_attached,
              :clusters_without_managed_master_secret,
              :clusters_with_default_master_username,
              :backup_retention_minimum_days

  DEFAULT_MASTER_USERNAMES = %w[admin postgres mysql sa root].freeze

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    @engines = Array(opts.delete(:engines)).map(&:to_s)
    @approved_engines = Array(opts.delete(:approved_engines)).map(&:to_s)
    @backup_retention_minimum_days = (opts.delete(:backup_retention_minimum_days) || 7).to_i
    super(opts)
    validate_parameters
    @clusters = []
    @clusters_without_storage_encrypted = []
    @clusters_without_in_transit_encryption = []
    @clusters_without_deletion_protection = []
    @clusters_without_backup_retention = []
    @clusters_without_audit_logging = []
    @clusters_without_auto_minor_upgrade = []
    @clusters_without_iam_authentication = []
    @clusters_in_default_vpc = []
    @clusters_with_open_security_groups = []
    @clusters_without_backup_window = []
    @clusters_without_multi_az = []
    @clusters_with_unapproved_engine = []
    @clusters_without_iam_role_attached = []
    @clusters_without_managed_master_secret = []
    @clusters_with_default_master_username = []
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    true
  end

  def to_s
    "RDS-API cluster compliance (engines=#{@engines.join(',')})"
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
    rds = ::Aws::RDS::Client.new(region: region)
    ec2 = ::Aws::EC2::Client.new(region: region)
    default_vpc = fetch_default_vpc(ec2)
    walk_clusters(rds, ec2, region, default_vpc)
  rescue ::Aws::Errors::ServiceError => e
    record_access_denied_or_warn("aws_rds_cluster_compliance", region, "fetch", e)
  end

  def fetch_default_vpc(ec2)
    resp = ec2.describe_vpcs(filters: [{ name: "is-default", values: ["true"] }])
    Array(resp.vpcs).first&.vpc_id
  rescue ::Aws::Errors::ServiceError
    nil
  end

  def walk_clusters(rds, ec2, region, default_vpc)
    next_marker = nil
    loop do
      resp =
        begin
          rds.describe_db_clusters(marker: next_marker)
        rescue ::Aws::Errors::ServiceError => e
          record_access_denied_or_warn("aws_rds_cluster_compliance", region, "describe_db_clusters", e)
          return
        end
      Array(resp.db_clusters).each do |c|
        next unless engine_matches?(c.engine)
        classify_cluster(rds, ec2, region, c, default_vpc)
      end
      break if resp.marker.nil? || resp.marker.empty?
      next_marker = resp.marker
    end
  end

  def engine_matches?(engine)
    return true if @engines.empty?
    @engines.any? { |e| engine.to_s == e || engine.to_s.start_with?(e) }
  end

  def classify_cluster(rds, ec2, region, cluster, default_vpc)
    record = {
      region:     region,
      cluster_id: cluster.db_cluster_identifier,
      engine:     cluster.engine,
      vpc_id:     fetch_vpc_id(rds, cluster),
    }
    @clusters << record

    @clusters_without_storage_encrypted << record unless cluster.storage_encrypted
    @clusters_without_deletion_protection << record unless cluster.deletion_protection
    @clusters_without_iam_authentication << record unless cluster.iam_database_authentication_enabled
    @clusters_without_backup_retention << record if cluster.backup_retention_period.to_i < @backup_retention_minimum_days
    @clusters_without_backup_window << record if cluster.preferred_backup_window.to_s.empty?
    @clusters_without_auto_minor_upgrade << record unless auto_minor_upgrade?(rds, cluster)

    audit_logs = Array(cluster.enabled_cloudwatch_logs_exports)
    @clusters_without_audit_logging << record if audit_logs.empty?

    in_transit = in_transit_encryption_enforced?(rds, cluster)
    @clusters_without_in_transit_encryption << record unless in_transit

    @clusters_in_default_vpc << record if default_vpc && record[:vpc_id] == default_vpc

    # Multi-AZ deployment: cluster has members in 2+ distinct AZs.
    @clusters_without_multi_az << record unless multi_az?(rds, cluster)

    # Engine must be in approved_engines (when input is non-empty).
    if !@approved_engines.empty? && !@approved_engines.include?(cluster.engine.to_s)
      @clusters_with_unapproved_engine << record
    end

    # IAM roles attached to the cluster (RDS associated_roles).
    @clusters_without_iam_role_attached << record if Array(cluster.associated_roles).empty?

    # Master credential management: either AWS-managed master secret
    # OR IAM database authentication. Either is acceptable; both off
    # means a manually-rotated password.
    has_managed_secret = cluster.respond_to?(:master_user_secret) && cluster.master_user_secret &&
                         !cluster.master_user_secret.secret_arn.to_s.empty?
    has_iam_auth = cluster.iam_database_authentication_enabled
    @clusters_without_managed_master_secret << record unless has_managed_secret || has_iam_auth

    # Default master_username — common defaults are weak (postgres, admin, root).
    if DEFAULT_MASTER_USERNAMES.include?(cluster.master_username.to_s.downcase)
      @clusters_with_default_master_username << record
    end
    @clusters_with_open_security_groups << record if open_to_world_security_group?(ec2, cluster)
  end

  def fetch_vpc_id(rds, cluster)
    member = Array(cluster.db_cluster_members).first
    return nil if member.nil?
    resp = rds.describe_db_instances(db_instance_identifier: member.db_instance_identifier)
    Array(resp.db_instances).first&.db_subnet_group&.vpc_id
  rescue ::Aws::Errors::ServiceError
    nil
  end

  def auto_minor_upgrade?(rds, cluster)
    member = Array(cluster.db_cluster_members).first
    return true if member.nil?
    resp = rds.describe_db_instances(db_instance_identifier: member.db_instance_identifier)
    Array(resp.db_instances).first&.auto_minor_version_upgrade == true
  rescue ::Aws::Errors::ServiceError
    false
  end

  def multi_az?(rds, cluster)
    members = Array(cluster.db_cluster_members)
    return false if members.empty?
    instance_ids = members.map(&:db_instance_identifier)
    azs =
      begin
        instance_ids.flat_map do |id|
          resp = rds.describe_db_instances(db_instance_identifier: id)
          Array(resp.db_instances).map(&:availability_zone)
        end
      rescue ::Aws::Errors::ServiceError
        []
      end
    azs.uniq.length >= 2
  end

  def in_transit_encryption_enforced?(rds, cluster)
    param = ENGINE_TLS_PARAM[cluster.engine.to_s]
    return true if param.nil?
    pg_name = cluster.db_cluster_parameter_group
    return false if pg_name.to_s.empty?
    next_marker = nil
    loop do
      resp =
        begin
          rds.describe_db_cluster_parameters(db_cluster_parameter_group_name: pg_name, marker: next_marker)
        rescue ::Aws::Errors::ServiceError
          return false
        end
      Array(resp.parameters).each do |p|
        next unless p.parameter_name.to_s == param
        return positive_value?(p.parameter_value)
      end
      break if resp.marker.nil? || resp.marker.empty?
      next_marker = resp.marker
    end
    false
  end

  def positive_value?(val)
    s = val.to_s.downcase
    %w[1 on yes true enabled].include?(s)
  end

  def open_to_world_security_group?(ec2, cluster)
    sg_ids = Array(cluster.vpc_security_groups).map(&:vpc_security_group_id)
    return false if sg_ids.empty?
    resp =
      begin
        ec2.describe_security_groups(group_ids: sg_ids)
      rescue ::Aws::Errors::ServiceError
        return false
      end
    Array(resp.security_groups).any? do |sg|
      Array(sg.ip_permissions).any? do |perm|
        Array(perm.ip_ranges).any? { |r| r.cidr_ip.to_s == "0.0.0.0/0" } ||
          Array(perm.ipv6_ranges).any? { |r| r.cidr_ipv6.to_s == "::/0" }
      end
    end
  end
end
