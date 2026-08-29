# encoding: UTF-8

control 'C-9.7' do
  title 'Ensure Monitoring and Alerting is Enabled'
  desc  "
    Alarm on cluster health and on failed authentication, and deliver the alarms to a
    destination a person actually monitors.

    An alarm delivered to an unconfirmed SNS subscription is silently discarded, so
    the monitoring appears configured while notifying nobody. Verifying the delivery
    path end to end is what separates this control from a configuration that merely
    looks correct.
  "
  desc  'rationale', "
    Alarm on cluster health and on failed authentication, and deliver the alarms to a
    destination a person actually monitors.

    An alarm delivered to an unconfirmed SNS subscription is silently discarded, so
    the monitoring appears configured while notifying nobody. Verifying the delivery
    path end to end is what separates this control from a configuration that merely
    looks correct.
  "
  desc  'check', "
    1. Sign in to the AWS Management Console 
    - Sign in to the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon Neptune Console
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/neptune/.

    3. Select the Neptune Cluster 
    - Choose the Amazon Neptune cluster on which you want to implement monitoring and alerting.
    - Click on the cluster name to access its details page.

    4. Set Up Amazon CloudWatch Metrics
    - In the cluster details page, navigate to the `Monitoring` or `Metrics` section.
    - Enable CloudWatch metrics for the Neptune cluster by clicking `Enable` or `Configure`.
    - Select the desired metrics to monitor, such as CPU utilization, storage usage, or network throughput.
    - Choose the appropriate granularity and sampling intervals for the metrics.
    - Click `Save` or `Apply Changes` to enable CloudWatch metrics for the Neptune cluster.

    5. Configure CloudWatch Alarms
    - In the CloudWatch console, navigate to `Alarms` in the left-side menu.
    - Click `Create alarm` to configure alarms based on specific metric thresholds.
    - Select the desired metric to monitor and set the threshold values for triggering an alarm.
    - Define the actions to be taken when the alarm state changes, such as sending notifications or triggering automated actions.
    - Configure the alarm settings, including alarm name, description, and notification recipients.
    - Click `Create alarm` to save the alarm configuration.

    6. Set Up Amazon EventBridge Rules
    - In the Amazon EventBridge console, navigate to `Rules` in the left-side menu.
    - Click on `Create rule` to set up rules for specific events or log entries related to Neptune.
    - Define the event pattern or log filter to match the desired events.
    - Configure the target actions to be taken when the rule matches an event, such as sending notifications or invoking AWS Lambda functions.
    - Specify the rule settings, including rule name, description, and event source.
    - Click `Create` to save the rule configuration.

    7. Review and Customize Metrics and Alarms
    - Periodically review the metrics and alarms configured for your Neptune cluster.
    - Adjust the metric thresholds and alarm settings based on your performance and alerting requirements.
    - Consider adding more metrics or alarms as needed to monitor additional aspects of your Neptune environment.

    8. Regularly Monitor and Respond to Alerts
    - Continuously monitor the CloudWatch metrics and alarm states for your Neptune cluster.
    - Respond promptly to any alarms triggered by critical or abnormal conditions.
    - Investigate the root causes of the alerts and take appropriate actions to mitigate issues.

    9. Utilize Additional Monitoring Tools 
    - Explore and leverage additional monitoring and observability tools available in the AWS ecosystem, such as Amazon CloudWatch Logs Insights, AWS X-Ray, or third-party monitoring solutions.
    - Configure these tools to gather insights and detect any performance or security issues in your Neptune environment.
  "
  desc  'fix', "
    1. Alarm on cluster health, CPU, freeable memory, replication lag and the gremlin
       or SPARQL error metrics, and deliver to a confirmed SNS subscription.
    2. Alarm on failed authentication attempts once IAM authentication is enabled.
    3. Enable Enhanced Monitoring for OS-level metrics on the instances.
    4. Verify the alarm path by driving an alarm into ALARM state rather than
       trusting the configuration.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'AU-1 a 1 (a)']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS']
  tag nist_r4:               ['AC-2 f', 'AU-1 a 1']
  tag cci:                   ['CCI-000011', 'CCI-000117']
  tag cis_number:            '9.7'
  tag cis_rid:               '9.7'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0907r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('neptune')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("NEPTUNE out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe aws_db_cloudwatch_alarms_coverage(regions: input('scan_regions'), namespaces: ['AWS/Neptune']) do
    its('namespaces_without_alarms') { should be_empty }
  end
end
