# encoding: UTF-8
#
# aws_timestream_audit_coverage — VERIFY (don't trust) that Timestream API
# activity is audit-logged. Built in-profile per each_profile_stands_alone
# (CIS 10.6 audit logging) — does NOT defer to cis-cloudtrail. Timestream has no
# native audit log; audit = CloudTrail data-event selectors covering Timestream.
# Checks every trail's advanced event selectors for a Timestream data-resource
# type (AWS::Timestream::Database / ::Table) or an all-data-events selector.
#
# exec_validated: false — describe_trails/get_event_selectors traversal not yet
# verified against a live account; validate before relying on a FAIL.
class AwsTimestreamAuditCoverage < AwsResourceBase
  name "aws_timestream_audit_coverage"
  desc "Whether a CloudTrail trail captures Timestream data events."
  example "
    describe aws_timestream_audit_coverage do
      it { should be_covered }
    end
  "
  def initialize(opts = {})
    super(opts)
    @covered = false
    catch_aws_errors do
      ct = @aws.cloudtrail_client
      Array(ct.describe_trails.trail_list).each do |t|
        sel = ct.get_event_selectors(trail_name: t.trail_arn)
        Array(sel.advanced_event_selectors).each do |aes|
          Array(aes.field_selectors).each do |fs|
            vals = Array(fs.equals) + Array(fs.starts_with)
            @covered = true if fs.field == "resources.type" &&
                               vals.any? { |v| v.to_s.start_with?("AWS::Timestream") }
          end
        end
        # classic selectors: a DataResource of type AWS::Timestream::* (or all)
        Array(sel.event_selectors).each do |es|
          Array(es.data_resources).each do |dr|
            @covered = true if dr.type.to_s.start_with?("AWS::Timestream")
          end
        end
      end
    end
  end

  def covered?
    @covered == true
  end

  def to_s
    "Timestream CloudTrail data-event coverage"
  end
end
