# encoding: UTF-8

control 'C-10.5' do
  title 'Ensure Fine-Grained Access Control is Enabled'
  desc  "
    Leverage Timestream's fine-grained access control capabilities to control table or row level access. Define access policies that limit access to specific tables, columns, or rows based on user roles or conditions. Implement data filtering and row-level security to restrict access to sensitive information.

    This helps by having specific permissions which can be denied due to multiple conditions of the database. This allows the user to control certain aspects of the database.
  "
  desc  'rationale', "
    Leverage Timestream's fine-grained access control capabilities to control table or row level access. Define access policies that limit access to specific tables, columns, or rows based on user roles or conditions. Implement data filtering and row-level security to restrict access to sensitive information.

    This helps by having specific permissions which can be denied due to multiple conditions of the database. This allows the user to control certain aspects of the database.
  "
  desc  'check', "
    1. Understand Fine-Grained Access Control in Timestream
    Familiarize yourself with the concept of fine-grained access control and its benefits in Timestream.
    Understand that fine-grained access control allows you to control access to specific tables, columns, or rows within Timestream databases.

    2. Define Timestream Database and Tables
    Create the necessary Timestream databases and tables that will be used for fine-grained access control.
    Design your database schema and define the tables, columns, and rows that need granular access control.

    3. Create IAM Policies for Fine-Grained Access
    Access the AWS Management Console and navigate to the IAM service.
    Define IAM policies that grant or deny permissions for specific Timestream actions, databases, tables, columns, or rows.
    Leverage Timestream's fine-grained access control policy language to specify the conditions and restrictions for access.

    4. Assign IAM Policies to IAM Users, Groups, or Roles
    Associate the IAM policies created earlier with the respective IAM users, groups, or roles.
    Assign the appropriate policies to grant access to specific Timestream databases, tables, columns, or rows.
    Follow the principle of least privilege and provide only the necessary permissions to users based on their requirements.

    5. Test Fine-Grained Access Control
    Validate the fine-grained access control settings by attempting different actions on Timestream databases, tables, columns, or rows.
    Verify that the defined policies accurately restrict or allow access based on the specified conditions.
    Perform thorough testing to enforce the expected granularity and security level.

    6. Regularly Review and Update Access Policies
    Periodically review the fine-grained access control policies to ensure they align with your organization's security requirements.
    Remove any unnecessary or outdated policies.
    Regularly monitor IAM activity logs and AWS CloudTrail to identify any unauthorized access attempts or unusual activities related to fine-grained access control.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '10.5'
  tag cis_rid:               '10.5'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-1005r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'operational'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('timestream')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("TIMESTREAM out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  ref = input('db_iam_attestation_reference').to_s
  rationale = ref.empty? ?
    "Requires manual review and attestation provided for this control (Timestream's table-level IAM policy granularity is consumer-policy-dependent; operators attest from their data-classification + per-table IAM policy review. Populate db_iam_attestation_reference input to surface the reference here)" :
    "Requires manual review and attestation provided for this control (consumer attestation: #{ref})"
  describe 'Timestream fine-grained access control' do
    skip rationale
  end
end
