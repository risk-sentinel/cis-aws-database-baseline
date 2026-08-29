# encoding: UTF-8

control 'C-10.8' do
  title 'Ensure Monitoring and Alerting is Enabled'
  desc  "
    Utilize Amazon CloudWatch to monitor key metrics, events, and logs related to Amazon Timestream. Set up appropriate alarms and notifications to detect security incidents or abnormal behavior proactively.

    This helps the individual know what is being logged within the activity and determine what next step should be if they spot any anomalies.
  "
  desc  'rationale', "
    Utilize Amazon CloudWatch to monitor key metrics, events, and logs related to Amazon Timestream. Set up appropriate alarms and notifications to detect security incidents or abnormal behavior proactively.

    This helps the individual know what is being logged within the activity and determine what next step should be if they spot any anomalies.
  "
  desc  'check', "
    1. Define Monitoring Objectives
    Determine the key metrics, events, and logs you want to monitor in Amazon Timestream.
    Identify the specific monitoring requirements based on your use case, workload, and business needs.

    2. Choose Monitoring Tools
    Evaluate the available monitoring tools for Amazon Timestream, such as AWS CloudWatch, third-party monitoring solutions, or custom-built monitoring systems.
    Select the monitoring tool that best aligns with your monitoring objectives and requirements.

    3. Configure CloudWatch Metrics
    Utilize Amazon CloudWatch to monitor key performance metrics of Timestream.
    Enable and configure CloudWatch metrics such as database CPU utilization, storage usage, query latency, and other relevant metrics.
    Set appropriate thresholds for these metrics to trigger alarms and notifications.

    4. Create CloudWatch Alarms
    Set up CloudWatch alarms based on your defined thresholds and monitoring objectives.
    Define the conditions that trigger the alarms, such as CPU utilization exceeding a certain percentage or query latency exceeding a specific threshold.
    Configure the notification actions for the alarms, such as sending notifications via email, SMS, or triggering automated actions.

    5. Enable Enhanced Monitoring (Optional)
    Consider enabling enhanced monitoring for Timestream, which provides more detailed performance metrics.
    Configure the enhanced monitoring settings to collect additional metrics that provide deeper insights into the health and performance of Timestream.

    6. Configure Log Streams and Filters
    Enable Timestream's integration with AWS CloudWatch Logs.
    Configure log streams and filters to capture and centralize Timestream logs into CloudWatch Logs.
    Define relevant log filters to extract and track specific log events for monitoring purposes.

    7. Regularly Review and Analyze Monitoring Data
    Continuously review the monitoring data and metrics CloudWatch provides or your chosen monitoring tool.
    Analyze the data to identify performance bottlenecks, anomalies, or issues in your Timestream implementation.
    Take necessary actions based on the monitoring insights to optimize performance, improve resource utilization, or troubleshoot issues.

    8. Periodically Review and Adjust Monitoring Configuration
    Regularly review your monitoring configuration to ensure it aligns with your evolving requirements and workload.
    Adjust your monitoring setup, such as adding or modifying metrics, updating alarm thresholds, or incorporating new log filters.
  "
  desc  'fix', "
    1. Alarm on ingestion errors and rejected records. Silently rejected records are
       the characteristic Timestream failure - the writer reports success for the
       batch while individual records are dropped.
    2. Alarm on query latency and on system errors, and on memory-store to
       magnetic-store transfer failures.
    3. Deliver to an SNS topic with a confirmed subscription, and verify the path end
       to end.
    4. Set memory-store and magnetic-store retention deliberately; data aged out of
       the memory store before it is queried is a data-loss condition that no alarm
       will report.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'AU-1 a 1 (a)']
  tag cci:                   ['CCI-000011', 'CCI-000117']
  tag cis_number:            '10.8'
  tag cis_rid:               '10.8'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-1008r1_rule'
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

  describe aws_db_cloudwatch_alarms_coverage(regions: input('scan_regions'), namespaces: ['AWS/Timestream']) do
    its('namespaces_without_alarms') { should be_empty }
  end
end
