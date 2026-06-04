# encoding: UTF-8
#
# aws_timestream_access_iam — VERIFY (don't trust) Timestream IAM access control.
# Built in-profile per each_profile_stands_alone (CIS 10.4 access control / 10.5
# fine-grained access) — does NOT defer the IAM question to cis-aws-foundations.
# Scans customer-managed (Scope=Local) IAM policies for Timestream grants:
#   - broad_admin_policies        : timestream:* (or write/admin verbs) on Resource:* (10.4)
#   - unscoped_resource_policies   : any timestream Allow on Resource:* (10.5 — FGAC means
#                                    per-database/per-table resource scoping, not "*")
#
# exec_validated: false — list_policies/get_policy_version scan not yet verified
# against a live account; validate before relying on a FAIL.
class AwsTimestreamAccessIam < AwsResourceBase
  name "aws_timestream_access_iam"
  desc "Customer-managed IAM policies granting broad/unscoped Timestream access."
  example "
    describe aws_timestream_access_iam do
      its('broad_admin_policies') { should be_empty }
      its('unscoped_resource_policies') { should be_empty }
    end
  "
  ADMIN_RE = /\Atimestream:(\*|Write|Create|Delete|Update|Describe.*|.*Table|.*Database)/i
  attr_reader :broad_admin_policies, :unscoped_resource_policies

  def initialize(opts = {})
    super(opts)
    @broad_admin_policies = []
    @unscoped_resource_policies = []
    catch_aws_errors do
      require "json"; require "cgi"
      iam = @aws.iam_client
      marker = nil
      loop do
        resp = iam.list_policies(scope: "Local", only_attached: false, marker: marker)
        Array(resp.policies).each do |p|
          ver = iam.get_policy_version(policy_arn: p.arn, version_id: p.default_version_id)
          doc = JSON.parse(CGI.unescape(ver.policy_version.document.to_s))
          Array(doc["Statement"]).each do |st|
            next unless st["Effect"] == "Allow"
            actions   = Array(st["Action"]).map(&:to_s)
            resources = Array(st["Resource"]).map(&:to_s)
            ts_action = actions.any? { |a| a == "*" || a =~ /\Atimestream:/i }
            next unless ts_action
            res_star  = resources.include?("*")
            @unscoped_resource_policies << p.policy_name if res_star
            broad_act = actions.any? { |a| a == "*" || a =~ ADMIN_RE }
            @broad_admin_policies << p.policy_name if res_star && broad_act
          end
        end
        break unless resp.is_truncated
        marker = resp.marker
      end
      @broad_admin_policies.uniq!
      @unscoped_resource_policies.uniq!
    end
  end

  def to_s
    "Timestream IAM access control"
  end
end
