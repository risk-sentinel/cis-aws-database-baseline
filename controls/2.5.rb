# encoding: UTF-8

control 'C-2.5' do
  title 'Ensure Database Audit Logging is Enabled'
  desc  "
    Amazon Aurora provides advanced auditing capabilities through AWS CloudTrail and Amazon RDS Database Activity Streams. Here is a step-by-step guide on how to enable and use these features:

    Allows individuals to access and retrieve their old logs, log their new events, and store their log.
  "
  desc  'rationale', "
    Amazon Aurora provides advanced auditing capabilities through AWS CloudTrail and Amazon RDS Database Activity Streams. Here is a step-by-step guide on how to enable and use these features:

    Allows individuals to access and retrieve their old logs, log their new events, and store their log.
  "
  desc  'check', "
    Below are the instructions for enabling logging through AWS CloudTrail:
    1. Sign in to AWS Management Console 
    - If you do not already have an AWS account, you will need to create one at https://aws.amazon.com.

    2. Navigate to CloudTrail Dashboard 
    - Navigate to the CloudTrail service. 
    - You can find this under the `Management & Governance` category.

    3. Create a new trail 
    - In the CloudTrail Dashboard, click on `Create trail`. 
    - Provide a name for the trail, and specify the S3 bucket where you want the logs to be stored.

    4. Configure trail settings 
    - Choose the settings that meet your requirements. For instance, you can log events for all regions, or you can log management events, data events, or both.

    5. Create the trail 
    - After specifying the trail settings, click `Create`.

    Below are the instructions for enabling logging through Amazon Database Activity Streams:
    1. Navigate to Amazon RDS Dashboard 
    - In the AWS Management Console, navigate to the RDS service. 
    - You can find this under the `Database` category.
    2. Choose your Aurora DB instance
    - In the RDS Dashboard, click on `Databases`, and then click on the name of your Aurora DB instance.
    3. Enable Database Activity Streams 
    - In the `Connectivity & Security` tab, find the `Database Activity Streams` section. Click `Create stream`.
    - In the `Create Stream` panel, choose the settings that meet your requirements and click `Create`.

    Note: Enabling Database Activity Streams can impact the performance of your DB instance, so you should test this feature in a non-production environment before enabling it in production.

    4. View the Database Activity Stream 
    - You can view the Database Activity Stream using Amazon Kinesis Data Streams. 
    - In the Kinesis Data Streams dashboard, click on the stream's name and then click `View data`.
  "
  desc  'fix', "
    Export the engine's audit log so it survives the instance and is queryable.

        ```
        aws rds modify-db-cluster --db-cluster-identifier <cluster-id> --cloudwatch-logs-export-configuration '{\"EnableLogTypes\":[\"audit\",\"error\",\"slowquery\"]}' --apply-immediately
        ```

    1. For Aurora MySQL, enable the audit plugin through the cluster parameter group
       (`server_audit_logging`, `server_audit_events`) - exporting alone produces no
       audit records if the plugin is off.
    2. For Aurora PostgreSQL, enable `pgaudit` in `shared_preload_libraries` and set
       `pgaudit.log` to the classes you need.
    3. Set a retention period on the CloudWatch log group. The default is never
       expire, which is a cost and a data-retention problem rather than a security
       one, but it should still be deliberate.
    4. Confirm records are arriving, rather than assuming the export took effect.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'AU-1 a 1 (a)']
  tag cci:                   ['CCI-000011', 'CCI-000117']
  tag cis_number:            '2.5'
  tag cis_rid:               '2.5'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0205r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('rds')
  impact 0.5
  scoped_items = scoped_or_na(aws_rds_clusters.entries,
                              in_scope: applicable_partition && applicable_service,
                              reason:   "RDS out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')}) or none present in this account")

  # CIS 2.5 asks for audit logging to be enabled on the database. The
  # technical surface for Aurora: enabled_cloudwatch_logs_exports on
  # the cluster must include at least one log stream (engine-specific
  # names — postgresql/audit — but the cluster-level "is anything
  # exported" check matches CIS intent without engine branching).
  #
  # Pre-cleanup the control had a logging_strategy_inherits? branch
  # that skipped with a boundary-inheritance rationale ("audit-log
  # delivery to a centralised destination satisfies the requirement at
  # the consumer's compliance boundary"). Removed per the
  # `each_profile_stands_alone` memory — cross-reference-to-foundations
  # attestation reasoning is rejected; each profile's controls must
  # carry their own technical check.
  allowed_engines = Array(input('rds_engines'))

  scoped_items.each do |c|
    next unless allowed_engines.empty? || allowed_engines.include?(c[:engine])

    describe aws_rds_cluster(db_cluster_identifier: c[:db_cluster_identifier]) do
      its('enabled_cloudwatch_logs_exports') { should_not be_empty }
    end
  end
end
