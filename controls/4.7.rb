# encoding: UTF-8

control 'C-4.7' do
  title 'Ensure Monitor and Audit Activity is enabled'
  desc  "
    Regular monitoring and auditing of activity in Amazon DynamoDB help ensure your database's security, performance, and compliance.

    This keeps track and ensures who has recently modified a document and monitors all activity within the database. This information allows the individual to use the details provided for auditing purposes and to address any compliance requirements.
  "
  desc  'rationale', "
    Regular monitoring and auditing of activity in Amazon DynamoDB help ensure your database's security, performance, and compliance.

    This keeps track and ensures who has recently modified a document and monitors all activity within the database. This information allows the individual to use the details provided for auditing purposes and to address any compliance requirements.
  "
  desc  'check', "
    1. Enable CloudTrail Logging for DynamoDB
    - Sign in to the AWS Management Console and open the CloudTrail console at https://console.aws.amazon.com/cloudtrail/.
    - Choose `Trails` from the left-side menu.
    - Click `Create trail` or select an existing trail.
    - Specify a trail name, choose an S3 bucket for storing logs, and configure other trail settings.
    - Under `Data events`, select the checkbox for `DynamoDB` to enable logging of DynamoDB data events.
    - Click `Create trail` or `Save changes` to save the CloudTrail configuration.

    2. Enable DynamoDB Streams
    - Sign in to the AWS Management Console and open the DynamoDB console at https://console.aws.amazon.com/dynamodb/.
    - Select the DynamoDB table you want to monitor.
    - Click on the `Overview` tab.
    - Under the `DynamoDB Streams` section, click `Manage stream`.
    - Enable DynamoDB Streams with the desired view type (e.g., `New and old images`).
    - Click `Enable`.

    3. Configure Amazon CloudWatch Alarms
    - Sign in to the AWS Management Console and open the CloudWatch console at https://console.aws.amazon.com/cloudwatch/.
    - In the left-side menu, click on `Alarms`.
    - Click `Create alarm`.
    - Select a DynamoDB metric to monitor (e.g., Read or Write capacity units).
    - Configure the threshold, conditions, and actions for the alarm.
    - Choose the actions to take when the alarm state is triggered (e.g., send notifications, auto-scaling actions, etc.).
    - Click `Create alarm` to save the configuration.

    4. Analyze and Review Logs and Metrics
    - Sign in to the AWS Management Console and open the CloudWatch console at https://console.aws.amazon.com/cloudwatch/.
    - In the left-side menu, click `Logs` to access CloudWatch Logs.
    - Select the appropriate log group for DynamoDB (e.g., `/aws/dynamodb/TableName`).
    - Review the logs to monitor activities, errors, and any unusual behavior.
    - Navigate to the CloudWatch console and click `Metrics` in the left-side menu.
    - Select the DynamoDB namespace and the desired metrics (e.g., ConsumedReadCapacityUnits, ConsumedWriteCapacityUnits).
    - Analyze the metrics to identify trends, capacity needs, and potential issues.

    5. Enable AWS Config for DynamoDB
    - Sign in to the AWS Management Console and open the AWS Config console at https://console.aws.amazon.com/config/.
    - Click on `Rules` in the left-side menu.
    - Click `Add rule`.
    - Configure a rule for DynamoDB compliance checks, such as checking for unencrypted tables or insecure IAM policies.
    - Customize the rule settings and scope based on your requirements.
    - Click `Save` to create the AWS Config rule.
  "
  desc  'fix', "
    1. Enable CloudTrail data events for the table. Management events alone record
       that the table was created, not that data was read from it:

        ```
        aws cloudtrail put-event-selectors --trail-name <trail> --advanced-event-selectors file://selectors.json
        ```

    2. Enable contributor insights to identify the most accessed keys, which is what
       surfaces a hot partition or an unexpected access pattern.
    3. Alarm on throttled requests, system errors, and unusual consumed capacity,
       and deliver to a confirmed SNS subscription.
    4. Set a retention period on the trail's log group and protect the trail with
       log file validation.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'AU-1 a 1 (a)']
  tag cci:                   ['CCI-000011', 'CCI-000117']
  tag cis_number:            '4.7'
  tag cis_rid:               '4.7'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0407r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('dynamodb')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("DYNAMODB out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe aws_db_cloudwatch_alarms_coverage(regions: input('scan_regions'), namespaces: ['AWS/DynamoDB']) do
    its('namespaces_without_alarms') { should be_empty }
  end
end
