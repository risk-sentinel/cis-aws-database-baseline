# encoding: UTF-8

control 'C-2.6' do
  title 'Ensure Passwords are Regularly Rotated'
  desc  "
    Regularly rotating your Aurora passwords is critical to access management, contributing to maintaining system security. The database password can be rotated in Amazon Aurora, but the access keys refer to the rotation of AWS IAM User access keys.

    Updating your password is critical to access AWS resources. This also ensures that your account is being kept safe from a potential threat.
  "
  desc  'rationale', "
    Regularly rotating your Aurora passwords is critical to access management, contributing to maintaining system security. The database password can be rotated in Amazon Aurora, but the access keys refer to the rotation of AWS IAM User access keys.

    Updating your password is critical to access AWS resources. This also ensures that your account is being kept safe from a potential threat.
  "
  desc  'check', "
    1. Sign in to AWS Management Console 
    - If you do not already have an AWS account, you will need to create one at https://aws.amazon.com.

    2. Navigate to Amazon RDS Dashboard 
    - Navigate to the RDS service once logged in to the AWS Management Console. You can find this under the `Database` category.

    3. Choose your Aurora DB instance 
    - In the RDS Dashboard, click on `Databases`, and then click on the name of your Aurora DB instance.

    4. Modify the instance 
    - Click `Modify`.
    - In the `Settings` section, enter a new password in the `Master password` and `Confirm password` fields.

    5. Apply the changes
    - Scroll to the bottom and choose when to apply the changes. You can apply them immediately or schedule them for the next maintenance window. 
    - Then, click `Continue` and `Modify DB Instance`.

    Note: Changing the master password will reboot the DB instance if you apply the change immediately.
  "
  desc  'fix', "
    Move the master credential into Secrets Manager with rotation enabled, so the
    password changes on a schedule without a human handling it.

        ```
        aws secretsmanager rotate-secret --secret-id <secret-arn> --rotation-lambda-arn <lambda-arn> --rotation-rules AutomaticallyAfterDays=30
        ```

    1. Where the engine supports it, prefer IAM database authentication for
       application sign-in. The token is valid for 15 minutes, so there is no
       long-lived password to rotate at all.
    2. Reserve the master credential for break-glass use, and alarm on its retrieval
       from Secrets Manager.
    3. Rotate any credential that has been exposed in a parameter store, a
       CloudFormation output, or an environment variable, rather than only going
       forward from now.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_number:            '2.6'
  tag cis_rid:               '2.6'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0206r1_rule'
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

  describe aws_rds_cluster_compliance(regions: input('scan_regions'), engines: input('rds_engines')) do
    its('clusters_without_managed_master_secret') { should be_empty }
  end
end
