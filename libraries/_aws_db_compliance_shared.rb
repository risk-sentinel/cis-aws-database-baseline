# Shared AccessDenied → connection_error helper for the cis-aws-database
# per-service compliance libraries (aws_rds_cluster_compliance,
# aws_redshift_compliance, aws_dynamodb_compliance,
# aws_elasticache_compliance, aws_memorydb_compliance,
# aws_timestream_compliance, aws_keyspaces_compliance,
# aws_db_cloudwatch_alarms_coverage).
#
# Background: each library used to rescue Aws::Errors::ServiceError and
# emit Inspec::Log.warn unconditionally. When the scanner role lacks
# the requisite IAM permissions for a service (the common case for
# consumers who don't use that service at all), the WARN replayed
# every time a control instantiated the resource — noisy CI output AND
# a vacuous-PASS risk on the empty-list accessors.
#
# Pattern: each library now calls `record_access_denied_or_warn(...)`
# inside its rescue blocks. AccessDenied errors set @connection_error
# (string), which the controls precheck per the
# Vendored_Resource_Gaps.md §5 pattern (Skip with rationale rather than
# vacuous PASS). Non-AccessDenied AWS errors still log a WARN —
# those represent genuinely-unexpected failures.
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

module AwsDbComplianceShared
  # Class names that AWS SDK Ruby uses for "denied / not authorized"
  # surfaces. Different services use slightly different shapes; some
  # raise the typed AccessDeniedException, others raise generic
  # ServiceError with a "not authorized" message. We check both.
  ACCESS_DENIED_CLASS_SUFFIXES = %w[
    AccessDeniedException
    AccessDenied
    UnauthorizedOperation
    AuthFailure
  ].freeze

  ACCESS_DENIED_MESSAGE_FRAGMENTS = [
    "AccessDenied",
    "not authorized",
    "is not authorized",
    "UnauthorizedOperation",
    "no cassandra:",
    "no permission",
  ].freeze

  # A failure that means "we could not look", as distinct from "the API said no
  # to this specific call". Endpoint-discovery services (Timestream) raise this
  # when the account is not entitled to the service at all: the SDK cannot even
  # resolve an endpoint, so nothing was ever asked.
  #
  # It matters that this sets connection_error rather than warning. Warning
  # leaves the collections empty, and an empty collection passes every
  # `should be_empty` assertion — so the control would report compliant having
  # assessed nothing. Not being able to look is not the same as there being
  # nothing to find.
  UNDETERMINABLE_MESSAGE_FRAGMENTS = [
    "Endpoint discovery failed",
    "discovered endpoint is not working",
  ].freeze

  def undeterminable_error?(err)
    return true if err.class.name.to_s.end_with?("EndpointDiscoveryError")
    msg = err.message.to_s
    UNDETERMINABLE_MESSAGE_FRAGMENTS.any? { |fragment| msg.include?(fragment) }
  end

  # Call from a `rescue Aws::Errors::ServiceError => e` block.
  # The receiver must be an instance with a writable @connection_error.
  def record_access_denied_or_warn(resource_label, region, op, err)
    if access_denied_error?(err) || undeterminable_error?(err)
      @connection_error ||= access_denied_message(resource_label, region, op, err)
    else
      ::Inspec::Log.warn("#{resource_label}: #{region} #{op} failed: #{err.class.name}: #{err.message}")
    end
  end

  def access_denied_error?(err)
    cls = err.class.name.to_s
    return true if ACCESS_DENIED_CLASS_SUFFIXES.any? { |suffix| cls.end_with?(suffix) }
    msg = err.message.to_s
    ACCESS_DENIED_MESSAGE_FRAGMENTS.any? { |fragment| msg.include?(fragment) }
  end

  private

  def access_denied_message(resource_label, region, op, err)
    "#{resource_label} #{op} in #{region} denied for the scanner role " \
      "(#{err.class.name}: #{err.message}). " \
      "Treating as 'consumer does not use this service or has not granted " \
      "the requisite IAM perms to the scanner role'. " \
      "Attest separately if the service IS in use."
  end
end
