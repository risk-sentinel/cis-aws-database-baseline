# encoding: UTF-8

control 'C-11.6' do
  title 'Ensure Monitoring and Logging is Enabled'
  desc  "
    Enable QLDB's built-in logging to capture important system events and database activity. Monitor the logs for any suspicious activities or errors. Leverage Amazon CloudWatch to collect and analyze logs, set up alarms, and receive notifications for potential security incidents.

    This helps the individual know what is being logged within the activity and determine what next step they should take to address it.
  "
  desc  'rationale', "
    Enable QLDB's built-in logging to capture important system events and database activity. Monitor the logs for any suspicious activities or errors. Leverage Amazon CloudWatch to collect and analyze logs, set up alarms, and receive notifications for potential security incidents.

    This helps the individual know what is being logged within the activity and determine what next step they should take to address it.
  "
  desc  'check', "
    1. Enable AWS CloudTrail
    - Sign in to the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.
    - Open the AWS CloudTrail console.
    - Create a new trail or select an existing trail.
    - Configure the trail to capture QLDB API calls and relevant events.
    - Specify the Amazon S3 bucket where the CloudTrail logs will be stored.
    - Enable the trail to start capturing QLDB events.

    2. Enable Amazon CloudWatch Logs
    - Open the Amazon CloudWatch console.
    - Create a new log group or select an existing log group.
    - Configure the log group to receive QLDB logs from CloudTrail.
    - Define the log retention period to retain the logs for the desired duration.
    - Enable CloudWatch Logs to start receiving and storing QLDB logs.

    3. Configure Log Metric Filters
    - In the CloudWatch console, go to the log group that contains the QLDB logs.
    - Define log metric filters to extract specific information or patterns from the logs.
    - Create metric filters based on your monitoring and alerting requirements.
    - Specify the target metric and define the filter patterns to match the desired log events.

    4. Create CloudWatch Dashboards and Alarms
    - Create CloudWatch dashboards to visualize and monitor important QLDB metrics.
    - Customize the dashboard widgets to display relevant log metrics, such as API calls or errors.
    - Set up CloudWatch alarms to trigger notifications or automated actions based on specific thresholds or conditions.
    - Configure alarm actions, such as sending email notifications or invoking AWS Lambda functions, to respond to critical events.

    5. Enable EventBridge Integration (Optional)
    - Open the Amazon EventBridge console.
    - Create a new rule or select an existing rule.
    - Configure the rule to match specific QLDB events or patterns.
    - Define targets for the rule, such as invoking Lambda functions or sending notifications to other AWS services.

    6. Monitor and Analyze Logs and Metrics
    - Regularly review the CloudWatch logs and metrics for QLDB.
    - Monitor key metrics and performance indicators to identify any issues or anomalies.
    - Use CloudWatch Logs Insights to query and analyze log data for troubleshooting.

    7. Integrate with AWS Monitoring and Alerting Tools
    - Leverage other AWS monitoring and alerting services like AWS X-Ray or AWS ServiceLens to gain deeper insights into QLDB performance and behavior.
    - Configure additional alerts or notifications using AWS services like Amazon SNS or AWS Chatbot.

    8. Regularly Review and Update Logging and Monitoring Configuration
    - Periodically review and update your CloudTrail, CloudWatch, and EventBridge configurations to align with changes in your monitoring requirements.
    - Stay informed about AWS security best practices and new features.
  "
  desc  'fix', "
    1. Enable CloudTrail management events for ledger lifecycle changes, and protect
       the trail with log file validation.
    2. Stream the journal to Kinesis so the immutable record of transactions is
       available for monitoring outside the ledger:

        ```
        aws qldb stream-journal-to-kinesis --ledger-name <ledger-name> --role-arn <role-arn> --kinesis-configuration StreamArn=<stream-arn> --inclusive-start-time <timestamp> --stream-name <stream-name>
        ```

    3. Alarm on `DeleteLedger`, `UpdateLedger` and changes to the KMS key.
    4. The journal is the audit record - verify its digest periodically rather than
       assuming immutability.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'AU-1 a 1 (a)']
  tag nist_r4:               ['AC-2 f', 'AU-1 a 1']
  tag cci:                   ['CCI-000011', 'CCI-000117']
  tag cis_number:            '11.6'
  tag cis_rid:               '11.6'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-1106r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('redshift')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("REDSHIFT out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe aws_redshift_compliance(regions: input('scan_regions')) do
    its('clusters_without_audit_logging') { should be_empty }
  end
end
