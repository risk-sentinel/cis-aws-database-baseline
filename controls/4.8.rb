# encoding: UTF-8

control 'C-4.8' do
  title 'Ensure Database has delete protection enabled'
  desc  "
    Ensure that delete protection is enabled on database instances to prevent accidental or unauthorized deletion. This setting safeguards critical databases by requiring explicit disabling of delete protection before deletion, reducing the risk of data loss through human error or malicious activity.

    Delete protection provides a safeguard against inadvertent or malicious deletion of critical databases. By requiring deliberate action to disable deletion protection, organizations mitigate risks associated with accidental data deletion and enhance the overall resilience of their data storage platform.
  "
  desc  'rationale', "
    Ensure that delete protection is enabled on database instances to prevent accidental or unauthorized deletion. This setting safeguards critical databases by requiring explicit disabling of delete protection before deletion, reducing the risk of data loss through human error or malicious activity.

    Delete protection provides a safeguard against inadvertent or malicious deletion of critical databases. By requiring deliberate action to disable deletion protection, organizations mitigate risks associated with accidental data deletion and enhance the overall resilience of their data storage platform.
  "
  desc  'check', "
    To check whether delete protection is enabled on your DynamoDB tables, use the following command for each table:

    ```
    aws dynamodb describe-table --table-name \\
      --query \"{TableName: Table.TableName, DeleteProtectionEnabled: Table.DeletionProtectionEnabled}\" \\
      --output table
    ```
    - Replace with your DynamoDB table name.
    - This will return True if delete protection is enabled, False otherwise.
  "
  desc  'fix', "
    To enable delete protection on an existing DynamoDB table, use the following command:

    ```
    aws dynamodb update-table \\
        --table-name my-table \\
        --deletion-protection-enabled
    ```
    - Replace with your DynamoDB table name.
    - Delete protection prevents the table from being deleted until the protection is disabled explicitly.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '4.8'
  tag cis_rid:               '4.8'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0408r1_rule'
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

  describe aws_dynamodb_compliance(regions: input('scan_regions')) do
    its('tables_without_deletion_protection') { should be_empty }
  end
end
