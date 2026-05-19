# encoding: UTF-8

control 'C-7.8' do
  title 'Ensure to Implement Monitoring and Alerting'
  desc  "
    This helps by alerting the system if any unusual event has occurred or if a particular threshold has been achieved because the user is able to set a desired interval or the cluster. This then allows system administrators to swiftly correct the situation and avoid subsequent complications if something unusual is happening.
  "
  desc  'rationale', "
    This helps by alerting the system if any unusual event has occurred or if a particular threshold has been achieved because the user is able to set a desired interval or the cluster. This then allows system administrators to swiftly correct the situation and avoid subsequent complications if something unusual is happening.
  "
  desc  'check', "
    1. Sign into the AWS Management Console
    - Sign into the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon DocumentDB Console
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/docdb/.

    3. Select the DocumentDB Cluster
    - Choose the Amazon DocumentDB cluster for which you want to implement monitoring and alerting. 
    - Click on the cluster name to access its details page.
    - In the cluster details page, navigate to the \"Monitoring\" section.

    4. Enable Enhanced Monitoring
    - Under the `Enhanced Monitoring` section.
    - Click on the `Edit` button or `Modify` option to configure enhanced monitoring settings.
    - Enable the desired metrics and set the desired monitoring interval for the cluster.
    - Enhanced monitoring provides additional insights into the performance and health of your DocumentDB cluster.

    5. Set Up CloudWatch Alarms
    - Scroll down to the `CloudWatch Alarms` section.
    - Click on the `Create alarm` button.
    - Configure the CloudWatch alarm based on the metrics you want to monitor and the thresholds you want to set.
    - Specify the actions to be taken when the alarm is triggered, such as sending notifications or executing automated actions.

    6. Customize Metrics and Dashboards (Optional)
    - If desired, you can customize the metrics and dashboards in Amazon CloudWatch to suit your specific monitoring requirements.
    - Create custom metrics, build personalized dashboards, and set up alarms based on your application's unique needs.

    7. Test Monitoring and Alerting
    - Perform operations on your DocumentDB cluster to generate metric data and trigger the configured alarms.
    - Verify that CloudWatch is capturing the metrics and triggering the appropriate actions based on your alarm settings.

    8. Regularly Review and Fine-Tune
    - Regularly review the monitoring metrics, CloudWatch alarms, and any event-driven actions triggered by DocumentDB events.
    - Fine-tune the monitoring settings, alarms, and notifications based on the observed patterns and requirements of your application.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'AU-1 a 1 (a)']
  tag cci:                   ['CCI-000011', 'CCI-000117']
  tag cis_number:            '7.8'
  tag cis_rid:               '7.8'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0708r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('documentdb')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("DOCUMENTDB out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe aws_db_cloudwatch_alarms_coverage(regions: input('scan_regions'), namespaces: ['AWS/DocDB']) do
    its('namespaces_without_alarms') { should be_empty }
  end
end
