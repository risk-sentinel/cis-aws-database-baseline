# encoding: UTF-8

control 'C-6.6' do
  title 'Ensure Monitoring and Alerting is Enabled'
  desc  "
    Implementing monitoring and alerting on Amazon MemoryDB allows you to proactively detect and respond to any performance issues, security events, or operational anomalies.

    This helps in ensuring that everything in the system is secure and if there is an unusual activity that takes place it addresses the issues quickly and efficiently.
  "
  desc  'rationale', "
    Implementing monitoring and alerting on Amazon MemoryDB allows you to proactively detect and respond to any performance issues, security events, or operational anomalies.

    This helps in ensuring that everything in the system is secure and if there is an unusual activity that takes place it addresses the issues quickly and efficiently.
  "
  desc  'check', "
    1. Sign into the AWS Management Console 
    - Sign into the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon MemoryDB Console
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/memorydb/.

    3. Select the Cluster 
    - Choose the Amazon MemoryDB cluster for which you want to implement monitoring and alerting. Click on the cluster name to access its details page.

    4. Enable Amazon CloudWatch
    - In the cluster details page, navigate to the `Monitoring` or `CloudWatch` section.
    - Click on `Enable` to enable CloudWatch monitoring for the cluster.
    - Select the appropriate CloudWatch metric categories to monitor, such as CPU utilization, memory utilization, network traffic, and storage capacity.
    - Configure the desired granularity and period for metric collection.
    - Click `Enable` or `Save` to enable CloudWatch monitoring for the cluster.

    5. Set Up CloudWatch Alarms
    - In the CloudWatch console, navigate to `Alarms` in the left-side menu.
    - Click on `Create Alarm` to set up a new alarm.
    - Select the CloudWatch metric related to the aspect you want to monitor, such as CPU utilization or memory utilization.
    - Configure the alarm threshold based on your desired criteria, such as setting CPU utilization above a certain percentage.
    - Define the actions to be taken when the alarm is triggered.
    - Click `Create Alarm` to create the CloudWatch alarm.

    6. Configure Amazon EventBridge Rules (Optional)
    - In the Amazon EventBridge console, navigate to `Rules` in the left-side menu.
    - Click on `Create rule` to set up a new rule.
    - Define the event pattern or source that should trigger the rule, such as specific MemoryDB events or errors.
    - Configure the target actions, such as sending notifications, executing AWS Lambda functions, or invoking AWS Step Functions.
    - Click `Create` to create the EventBridge rule.

    7. Configure Auto Scaling (Optional)
    - In the MemoryDB cluster details page, navigate to the `Auto Scaling` section.
    - Configure auto-scaling settings based on your workload and performance requirements.
    - Define the scaling policies, such as increasing or decreasing the number of replica nodes based on CPU utilization or other metrics.
    - Set the desired minimum and maximum number of replica nodes for the cluster.
    - Click `Save` or `Apply Changes` to apply the auto-scaling configuration.

    8. Regularly Review and Adjust Monitoring and Alarms
    - Periodically review the CloudWatch metrics and alarms to ensure they align with your monitoring needs and performance expectations.
    - Adjust the thresholds and actions based on changing workload patterns or performance requirements.
    - Stay informed about new CloudWatch features and best practices to optimize your monitoring setup.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'AU-1 a 1 (a)']
  tag cci:                   ['CCI-000011', 'CCI-000117']
  tag cis_number:            '6.6'
  tag cis_rid:               '6.6'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0606r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('memorydb')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("MEMORYDB out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe aws_db_cloudwatch_alarms_coverage(regions: input('scan_regions'), namespaces: ['AWS/MemoryDB']) do
    its('namespaces_without_alarms') { should be_empty }
  end
end
