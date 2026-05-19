# Per-region enumeration of Redshift clusters for CIS §11.4 / §11.6.
#
# §11.4 — Data in Transit Encrypted. Redshift checks the cluster's
# parameter group for `require_ssl == true`.
#
# §11.6 — Monitoring and Logging. Redshift exposes
# `describe_logging_status(cluster_identifier)` returning
# `logging_enabled` + `bucket_name` for the audit logs S3 destination.
#
# Per-region instantiation. aws-sdk-redshift IS bundled in stock cinc-auditor.
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsRedshiftCompliance < AwsResourceBase
  include AwsDbComplianceShared

  name "aws_redshift_compliance"
  desc "Redshift compliance accessors (CIS §11.4 / §11.6)."
  example "
    inv = aws_redshift_compliance
    describe inv do
      its('clusters_without_in_transit_encryption') { should be_empty }
      its('clusters_without_audit_logging')         { should be_empty }
    end
  "

  DEFAULT_MASTER_USERNAMES = %w[awsuser admin root].freeze

  attr_reader :clusters,
              :clusters_without_in_transit_encryption,
              :clusters_without_audit_logging,
              :clusters_without_iam_roles,
              :clusters_with_default_master_username

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @clusters = []
    @clusters_without_in_transit_encryption = []
    @clusters_without_audit_logging = []
    @clusters_without_iam_roles = []
    @clusters_with_default_master_username = []
    @regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    true
  end

  def to_s
    "Redshift compliance"
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
    client = ::Aws::Redshift::Client.new(region: region)
    next_marker = nil
    loop do
      resp =
        begin
          client.describe_clusters(marker: next_marker)
        rescue ::Aws::Errors::ServiceError => e
          record_access_denied_or_warn("aws_redshift_compliance", region, "describe_clusters", e)
          return
        end
      Array(resp.clusters).each { |c| classify(client, region, c) }
      break if resp.marker.nil? || resp.marker.empty?
      next_marker = resp.marker
    end
  end

  def classify(client, region, cluster)
    record = { region: region, cluster_id: cluster.cluster_identifier }
    @clusters << record
    @clusters_without_in_transit_encryption << record unless require_ssl?(client, cluster)
    @clusters_without_audit_logging << record unless audit_logging_enabled?(client, cluster)

    # C-11.1: at least one IAM role attached to the cluster (IAM-based
    # access from compute is the recommended pattern over IAM users).
    iam_roles = Array(cluster.iam_roles)
    @clusters_without_iam_roles << record if iam_roles.empty?

    # C-11.5: master_username must not be a service default — those are
    # weak / well-known and should be replaced.
    if DEFAULT_MASTER_USERNAMES.include?(cluster.master_username.to_s.downcase)
      @clusters_with_default_master_username << record
    end
  end

  def require_ssl?(client, cluster)
    pg_name = Array(cluster.cluster_parameter_groups).first&.parameter_group_name
    return false if pg_name.to_s.empty?
    next_marker = nil
    loop do
      resp =
        begin
          client.describe_cluster_parameters(parameter_group_name: pg_name, marker: next_marker)
        rescue ::Aws::Errors::ServiceError
          return false
        end
      Array(resp.parameters).each do |p|
        next unless p.parameter_name.to_s == "require_ssl"
        return p.parameter_value.to_s.downcase == "true"
      end
      break if resp.marker.nil? || resp.marker.empty?
      next_marker = resp.marker
    end
    false
  end

  def audit_logging_enabled?(client, cluster)
    resp = client.describe_logging_status(cluster_identifier: cluster.cluster_identifier)
    resp.logging_enabled == true
  rescue ::Aws::Errors::ServiceError
    false
  end
end
