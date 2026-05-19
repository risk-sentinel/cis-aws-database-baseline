# encoding: UTF-8

control 'C-3.9' do
  title 'Ensure Monitoring and Logging is Enabled'
  desc  "
    TODO: description missing in source XCCDF
  "
  desc  'rationale', "
    TODO: description missing in source XCCDF
  "
  desc  'check', "
    1. Sign into the AWS Management Console
    - Sign into the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon RDS Console 
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/rds/.

    3. Select the RDS Instance 
    - Choose the Amazon RDS instance you want to enable monitoring and logging.
    - Click on the instance name to access its details page.
    - In the instance details page, navigate to the `Configuration` or `Monitoring & Logs` section.

    4. Enable Enhanced Monitoring
    - Under the `Monitoring` section.
    - Click on the `Modify` button or `Edit` option to enable enhanced monitoring.
    - Choose the desired monitoring granularity (1-minute or 5-minute intervals) and the retention period for the monitoring data.
    - Click `Continue` or `Save` to apply the changes.

    5. Enable Enhanced Logging
    - Under the `Logs` or `Monitoring & Logs` section.
    - Click on the `Modify` button or `Edit` option to enable enhanced logging.
    - Choose the desired log types to enable, such as general, error, slow query, or audit logs.
    - Configure the log file retention period based on your needs.
    - Select the destination for the logs, such as Amazon CloudWatch Logs or an Amazon S3 bucket.
    - Configure the log format and other settings if applicable.
    - Click `Continue` or `Save` to apply the changes.

    6. Configure CloudWatch Alarms (Optional)
    - Click `Alarms` in the Amazon RDS console menu.
    - Click `Create alarm` to create a CloudWatch alarm to monitor specific metrics or log events.
    - Configure the alarm threshold, actions to take when the threshold is breached, and notification settings.
    - Click `Create` to create the CloudWatch alarm.

    7. Monitor and Analyze the Metrics and Logs
    - Monitor the metrics and logs in the Amazon RDS console or by accessing CloudWatch or the configured log destination.
    - Use the metrics and logs to gain insights into your RDS instance's performance, behavior, and issues.
    - Analyze the metrics and logs to identify areas for optimization, troubleshoot problems, or detect anomalies.

    8. Set Up Automated Actions (Optional)
    - In the Amazon RDS console, click on `Event subscriptions` in the left-side menu.
    - Click `Create event subscription` to set up automated actions based on specific events or log entries.
    - Configure the event pattern, target actions, and notification settings.
    - Click `Create` to create the event subscription.

    9. Monitor and Respond to Alerts
    - Monitor the CloudWatch alarms and event notifications for any alerts or triggers based on the configured thresholds.
    - Respond to alerts promptly by investigating and resolving the underlying issues or taking appropriate actions.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '3.9'
  tag cis_rid:               '3.9'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0309r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('rds')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("RDS out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  # CIS 3.9 asks for both Enhanced Monitoring and log exports. Enhanced
  # Monitoring is instance-level (monitoring_interval > 0 means enabled).
  # Log exports live at the cluster level in Aurora.
  allowed_engines = Array(input('rds_engines'))

  aws_rds_instances.entries.each do |i|
    next unless allowed_engines.empty? || allowed_engines.include?(i[:engine])

    describe aws_rds_instance(db_instance_identifier: i[:db_instance_identifier]) do
      its('monitoring_interval') { should be > 0 }
    end
  end

  aws_rds_clusters.entries.each do |c|
    next unless allowed_engines.empty? || allowed_engines.include?(c[:engine])

    describe aws_rds_cluster(db_cluster_identifier: c[:db_cluster_identifier]) do
      its('enabled_cloudwatch_logs_exports') { should_not be_empty }
    end
  end
end
