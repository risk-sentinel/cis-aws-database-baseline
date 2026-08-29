# encoding: UTF-8

control 'C-5.6' do
  title 'Ensure Monitoring and Logging is Enabled'
  desc  "
    Implementing monitoring and logging for Amazon ElastiCache allows you to gain visibility into the performance, health, and behavior of your ElastiCache clusters.

    This helps the individual know what is being logged within the activity and determine what next step they should take to address any suspicious activity.
  "
  desc  'rationale', "
    Implementing monitoring and logging for Amazon ElastiCache allows you to gain visibility into the performance, health, and behavior of your ElastiCache clusters.

    This helps the individual know what is being logged within the activity and determine what next step they should take to address any suspicious activity.
  "
  desc  'check', "
    1. Sign in to the AWS Management Console
    - Sign in to the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the ElastiCache Console
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/elasticache/.

    3. Select the ElastiCache Cluster
    - Choose the ElastiCache cluster for which you want to implement monitoring and logging. 
    - Click on the cluster name to access its details page.

    4. Enable Enhanced Monitoring
    - Click on the `Monitoring` tab on the cluster details page.
    - Under the `Monitoring` section, click on the `Enable Enhanced Monitoring` button.
    - Select the desired monitoring granularity (1 minute, 5 minutes, or 60 minutes) to capture detailed metrics.
    - Choose the desired CloudWatch namespace to store the metrics.
    - Click `Save changes` to enable enhanced monitoring for the ElastiCache cluster.

    5. Set Up CloudWatch Alarms
    - In the CloudWatch console, navigate to `Alarms` in the left-side menu.
    - Click `Create alarm` to create a new alarm.
    - Select the appropriate ElastiCache metrics from the available options.
    - Configure the threshold, conditions, and actions for the alarm.
    - Choose the actions to take when the alarm state is triggered (e.g., send notifications, auto-scaling actions, etc.).
    - Click `Create alarm` to save the alarm configuration.

    6. Configure CloudWatch Logs
    - In the CloudWatch console, navigate to `Logs` in the left-side menu.
    - Click `Create log group` to create a new one.
    - Provide a unique name for the log group and optionally specify a retention period for log data.
    - Click `Create log group` to create the log group.
    - On the ElastiCache cluster details page, click the `Logging` tab.
    - Enable the `CloudWatch Logs` option and select the desired log group from the dropdown menu.
    - Click `Save changes` to enable CloudWatch Logs for the ElastiCache cluster.

    7. Verify Monitoring and Logging
    - Wait a few minutes for the monitoring and logging configurations to take effect.
    - Refresh the cluster details page for the updated monitoring and logging status.
    - Navigate to the CloudWatch console to view metrics, alarms, and logs related to your ElastiCache cluster.
  "
  desc  'fix', "
    The individual can understand the health, performance, and behavior of their clusters which allows them to address any unusual activity that takes place.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'AU-1 a 1 (a)']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS']
  tag nist_r4:               ['AC-2 f', 'AU-1 a 1']
  tag cci:                   ['CCI-000011', 'CCI-000117']
  tag cis_number:            '5.6'
  tag cis_rid:               '5.6'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0506r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('elasticache')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("ELASTICACHE out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe aws_db_cloudwatch_alarms_coverage(regions: input('scan_regions'), namespaces: ['AWS/ElastiCache']) do
    its('namespaces_without_alarms') { should be_empty }
  end
end
