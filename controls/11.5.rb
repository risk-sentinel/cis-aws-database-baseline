# encoding: UTF-8

control 'C-11.5' do
  title 'Ensure to Implement Access Control and Authentication'
  desc  "
    Utilize QLDB's built-in authentication and access control mechanisms. Define IAM policies to control which users or roles can perform specific actions on QLDB resources. Leverage IAM roles for cross-service access, securely integrating QLDB with other AWS services.

    Users should select whether they like to enable authentication. If they want to authenticate the user would be required to implement IAM roles would grant or deny permissions within that database.
  "
  desc  'rationale', "
    Utilize QLDB's built-in authentication and access control mechanisms. Define IAM policies to control which users or roles can perform specific actions on QLDB resources. Leverage IAM roles for cross-service access, securely integrating QLDB with other AWS services.

    Users should select whether they like to enable authentication. If they want to authenticate the user would be required to implement IAM roles would grant or deny permissions within that database.
  "
  desc  'check', "
    1. Understand QLDB Authentication and Access Control
    - Familiarize yourself with the authentication and access control mechanisms provided by QLDB.
    - Understand the concepts of users, permissions, and roles in QLDB's access control model.

    2. Configure IAM for QLDB
    - Sign in to the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.
    - Open the Amazon QLDB console.
    - Go to the `Ledgers` section.
    - Select the QLDB ledger for which you want to configure access control.
    - Under the `Configuration` tab.
    - Click on `Edit` or `Modify` to make changes.
    - Enable IAM-based authentication by selecting the appropriate option.
    - Define the IAM policies that grant or deny permissions for specific QLDB actions.
    - Configure fine-grained access control by associating IAM policies with IAM users or roles.

    3. Create IAM Users or Roles
    - Identify the individuals or services that require access to QLDB.
    - Create IAM user accounts for individuals or IAM roles for services.
    - Assign appropriate IAM policies to these users or roles based on their required access levels.

    4. Grant Required Permissions
    - Define IAM policies that grant the necessary permissions for QLDB operations.
    - Consider the principle of least privilege and only provide the minimum permissions required for each user or role.
    - Assign IAM policies to IAM users or roles to allow access to specific QLDB resources.

    5. Test Access Control
    - Use IAM user credentials or IAM role credentials to test access to QLDB resources.
    - Verify that users or services can perform the expected actions based on their assigned IAM policies.
    - Test both read and write operations to ensure appropriate access permissions.

    6. Monitor and Audit Access
    - Enable AWS CloudTrail for QLDB to capture and log all API calls and activities.
    - Use Amazon CloudWatch to monitor and analyze the logs for unauthorized access attempts or suspicious activities.
    - Implement additional logging and auditing mechanisms as per your organization's security requirements.

    7. Regularly Review and Update Access Control
    - Conduct periodic reviews of IAM policies, users, and roles associated with QLDB.
    - Remove or update access for users or roles that no longer require QLDB access.
    - Stay updated with AWS security best practices and IAM and access control recommendations.
  "
  desc  'fix', "
    1. Use IAM roles assumed by the workload; QLDB has no database-local user
       directory, so IAM is the entire authentication and authorisation story.
    2. Scope policies to the ledger ARN, and where the driver supports it, to the
       specific table resources for `qldb:PartiQL*` actions.
    3. Separate the role that writes transactions from the role that reads the
       journal, and keep export and administrative actions apart from both.
    4. Review with IAM Access Analyzer and remove unused permissions.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '11.5'
  tag cis_rid:               '11.5'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-1105r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('redshift')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("REDSHIFT out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe aws_redshift_compliance(regions: input('scan_regions')) do
    its('clusters_without_iam_roles')             { should be_empty }
    its('clusters_with_default_master_username')  { should be_empty }
  end
end
