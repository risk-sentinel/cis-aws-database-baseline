# Custom resource wrapping `describe_db_cluster_parameters` so controls
# can assert on individual parameter values inside an RDS / Aurora
# cluster parameter group. Added for CIS AWS Database Services 2.3
# (rds.force_ssl for Aurora-Postgres; require_secure_transport for
# Aurora-MySQL); reusable for any future parameter-group check.
#
# Not in inspec-aws 1.83.63 — the vendored `aws_rds_cluster` resource
# only exposes the parameter group *name* as a dynamic method, not the
# parameter values themselves.
#
# Depends on `_aws_backend_bootstrap.rb` having been loaded first (its
# leading underscore sorts it before this file in InSpec's alphabetical
# library-load order).
#
# Uses @aws.rds_client (exposed directly by train-aws's AwsConnection,
# same accessor the vendored aws_rds_cluster resource uses). No need
# for the generic aws_client(klass) path.

class AwsRdsClusterParameterGroup < AwsResourceBase
  name "aws_rds_cluster_parameter_group"
  desc "RDS / Aurora cluster parameter group — inspect individual parameter values."
  example "
    describe aws_rds_cluster_parameter_group(name: 'default.aurora-postgresql15') do
      it { should exist }
      its('parameter_value(\"rds.force_ssl\")') { should eq '1' }
    end
  "

  attr_reader :group_name, :parameters

  def initialize(opts = {})
    opts = { name: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: [:name])
    @group_name = opts[:name]
    @parameters = fetch_parameters
  end

  def exists?
    !@parameters.nil? && !@parameters.empty?
  end

  # Lookup a parameter's current value by name. Returns the
  # ParameterValue string (AWS stores all parameter values as strings —
  # "1", "ON", "30", etc.), or nil if the parameter is not present in
  # the group.
  def parameter_value(name)
    row = @parameters.find { |p| p[:parameter_name] == name }
    row && row[:parameter_value]
  end

  # Return the full parameter hash (parameter_name, parameter_value,
  # apply_method, source, description, ...) for named parameter, or nil.
  # Useful for controls that need more than just the value (e.g. to
  # check apply_method == 'pending-reboot').
  def parameter(name)
    @parameters.find { |p| p[:parameter_name] == name }
  end

  # Convenience predicate for Postgres: rds.force_ssl = 1.
  def force_ssl_enabled?
    parameter_value("rds.force_ssl") == "1"
  end

  # Convenience predicate for MySQL: require_secure_transport = ON.
  def require_secure_transport_enabled?
    v = parameter_value("require_secure_transport").to_s.upcase
    v == "ON" || v == "1"
  end

  def to_s
    "RDS Cluster Parameter Group: #{@group_name}"
  end

  private

  def fetch_parameters
    rows = []
    catch_aws_errors do
      pagination = { db_cluster_parameter_group_name: @group_name }
      loop do
        resp = @aws.rds_client.describe_db_cluster_parameters(pagination)
        Array(resp.parameters).each do |p|
          rows << p.to_h
        end
        break unless resp.marker
        pagination[:marker] = resp.marker
      end
    end
    rows
  end
end
