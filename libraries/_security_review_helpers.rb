# frozen_string_literal: true

require 'date'

# DbSecurityReviewHelpers provides a shared cadence-check used by the
# six CIS AWS Database "regularly review security configuration"
# controls (C-3.11 RDS, C-5.7 ElastiCache, C-5.10 ElastiCache, C-6.5
# MemoryDB, C-9.6 Neptune, C-10.9 Timestream). Replaces what used to
# be an attestation skip with an inputs-driven assertion:
#
#   db_security_review_last_date        — ISO date of last review (required).
#   db_security_review_cadence_days     — Max age in days (default 365).
#   db_security_review_attestation_reference — Optional evidence URL/path.
#
# Status enum:
#   :unconfigured — last_date input empty; FAIL (consumer must populate).
#   :malformed    — last_date input not parseable as ISO date; FAIL.
#   :overdue      — last review older than cadence_days; FAIL.
#   :current      — within cadence; PASS.
module DbSecurityReviewHelpers
  def db_security_review_status
    raw = input('db_security_review_last_date').to_s.strip
    return [:unconfigured, nil, nil] if raw.empty?

    last_date =
      begin
        Date.parse(raw)
      rescue ArgumentError, TypeError
        nil
      end
    return [:malformed, raw, nil] if last_date.nil?

    cadence = Integer(input('db_security_review_cadence_days') || 365)
    age_days = (Date.today - last_date).to_i
    status = age_days <= cadence ? :current : :overdue
    [status, last_date, age_days]
  end

  def db_security_review_failure_message(status, last_date, age_days, service_label)
    cadence = input('db_security_review_cadence_days') || 365
    ref = input('db_security_review_attestation_reference').to_s
    evidence = ref.empty? ? '' : " (evidence: #{ref})"

    case status
    when :unconfigured
      "Set db_security_review_last_date to the ISO date of your most recent #{service_label} security-configuration review. Empty input means CIS has no review-cadence rule to evaluate against; FAIL rather than silently skipping."
    when :malformed
      "db_security_review_last_date=#{last_date.inspect} is not a parseable ISO date (e.g., 2026-04-15)."
    when :overdue
      "Last #{service_label} security-configuration review was #{age_days} days ago on #{last_date}, exceeding the configured cadence of #{cadence} days#{evidence}."
    else
      nil
    end
  end
end

::Inspec::Rule.include(DbSecurityReviewHelpers)
