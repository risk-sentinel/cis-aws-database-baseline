# encoding: UTF-8

control 'C-10.6' do
  title 'Ensure Audit Logging is Enabled'
  desc  "
    Enable AWS CloudTrail to capture and log API calls and activities related to Amazon Timestream. Configure CloudTrail to store the logs in a secure location and regularly review the logs for any unauthorized or suspicious activities.

    This captures and saves logs of activities that took place in the database.
  "
  desc  'rationale', "
    Enable AWS CloudTrail to capture and log API calls and activities related to Amazon Timestream. Configure CloudTrail to store the logs in a secure location and regularly review the logs for any unauthorized or suspicious activities.

    This captures and saves logs of activities that took place in the database.
  "
  desc  'check', "
    1. Understand Audit Logging in Timestream
    Familiarize yourself with audit logging and its importance in monitoring and tracking activities in Timestream.
    Understand that audit logs capture API calls and events related to Timestream actions and resources.

    2. Enable AWS CloudTrail
    Access the AWS Management Console and navigate to the AWS CloudTrail service.
    Create a new CloudTrail trail or use an existing one to capture Timestream audit logs.
    Configure the trail to include Timestream as a data source for logging.

    3. Configure CloudTrail Logging Options
    Specify the desired settings for the CloudTrail trail, such as the S3 bucket to store the audit logs and the log file encryption options.
    Enable logging of management and data events related to Timestream.
    Configure the trail to capture the necessary information for your audit and compliance requirements.

    4. Set Up CloudTrail Notifications and Alerts
    Configure CloudTrail to send notifications or trigger actions based on specific events or conditions.
    Set up CloudWatch Alarms to monitor and receive notifications for critical Timestream audit events.
    Define the appropriate alert thresholds and actions to respond to specific events.

    5. Access and Review Audit Logs
    Access the configured S3 bucket where the Timestream audit logs are stored.
    Retrieve and review the logs using AWS Management Console, AWS CLI, or any preferred log analysis tools.
    Analyze the audit logs to track Timestream activities, detect anomalies, and investigate security incidents.

    6. Retention and Compliance Considerations
    Determine the appropriate retention period for your Timestream audit logs based on compliance and regulatory requirements.
    Implement appropriate data lifecycle management policies for your audit logs stored in the S3 bucket.
    Ensure compliance with data protection and privacy regulations applicable to your organization.

    7. Regularly Review and Monitor Audit Logs
    Establish a regular review process for your Timestream audit logs.
    Monitor the logs for unauthorized access attempts, unusual activities, or policy violations.
    Respond promptly to any identified security incidents or anomalies.
  "
  desc  'fix', "
    1. Enable CloudTrail management events to record database and table changes.
    2. Timestream does not emit a per-query audit log, so pair CloudTrail with
       CloudWatch metrics for query and ingestion volume, and treat an unexplained
       change in read volume as the signal worth alerting on.
    3. Protect the trail with log file validation, set retention on the log group,
       and confirm events are arriving.
    4. Alarm specifically on `DeleteTable`, `DeleteDatabase` and changes to the KMS
       key.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'AU-1 a 1 (a)']
  tag cci:                   ['CCI-000011', 'CCI-000117']
  tag cis_number:            '10.6'
  tag cis_rid:               '10.6'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-1006r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('timestream')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("TIMESTREAM out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  # VERIFY-don't-trust + each_profile_stands_alone (Phase C correction): built
  # in-profile (NOT deferred to foundations IAM / cloudtrail). VERIFY by default;
  # attestation is an explicit opt-out (set c_10_6_attestation_uri).
  uri = input('c_10_6_attestation_uri', value: '')
  if uri.to_s.empty?
    describe aws_timestream_audit_coverage do
      it { should be_covered }
    end
  else
    doc = document_attestation(uri, max_age_days: input('attestation_max_age_days', value: 365))
    describe "Timestream audit logging attestation (#{uri})" do
      it('is reachable') { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it('exists') { expect(doc.exists?).to eq(true) }
      it('is current') { expect(doc.current?).to eq(true) }
    end
  end
end