# encoding: UTF-8

control 'C-3.7' do
  title 'Ensure to Implement Access Control and Authentication'
  desc  "
    Users should select whether they like to enable authentication. If they want to authenticate a password would be required, which would only allow the authorized person to access the database. Defining access control allows specific workers in a business access to the database.
  "
  desc  'rationale', "
    Users should select whether they like to enable authentication. If they want to authenticate a password would be required, which would only allow the authorized person to access the database. Defining access control allows specific workers in a business access to the database.
  "
  desc  'check', "
    1. Sign into the AWS Management Console 
    - Sign into the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon RDS Console 
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/rds/.

    3. Select the RDS Instance 
    - Choose the Amazon RDS instance you want to implement access control and authentication. 
    - Click on the instance name to access its details page.
    - In the instance details page, navigate to the `Configuration` or `Connectivity & Security` section.

    4. Enable IAM Database Authentication
    - Under the `Connectivity` or `Connectivity & Security` section.
    - Click the `Modify` or `Edit` option to enable IAM Database Authentication.
    - Select the option to enable IAM Database Authentication.
    - Click `Continue` or `Save` to apply the changes.

    5. Create and Configure IAM Database Users
    - Click `Users` in the left-side menu in the Amazon RDS console.
    - Click `Create database user` to create a new IAM database user.
    - Provide a username and select the IAM role or IAM user that will be associated with the database user.
    - Configure the authentication type, either `Password-based` or `IAM authentication`.
    - Set the desired password or leave it blank for IAM authentication.
    - Configure the database user's privileges and permissions based on your application's requirements.
    - Click `Create` to create the IAM database user.

    6. Configure Database User Privileges
    - Click `Users` in the left-side menu in the Amazon RDS console.
    - Select the database user you created in the previous step.
    - Click on `Modify` to modify the user's settings and permissions.
    - Configure the user's access privileges, including database access, object permissions, and privileges.
    - Click `Save` or `Apply Changes` to update the user's privileges.

    7. Test Access and Authentication
    - Test the access and authentication by connecting to the RDS instance using the IAM database user's credentials or IAM role.
    - Verify that the authentication and access control mechanisms are functioning correctly.

    8. Monitor and Manage IAM Database Users
    - Regularly monitor and review the IAM database users and their access privileges.
    - Adjust user privileges as needed based on changes in your application requirements.
    - Remove or disable database users when they are no longer needed.
  "
  desc  'fix', "
    1. Enable IAM database authentication so sign-in uses a short-lived token tied to
       an IAM principal rather than a shared password:

        ```
        aws rds modify-db-instance --db-instance-identifier <instance-id> --enable-iam-database-authentication --apply-immediately
        ```

    2. Create the database user with the engine's IAM auth grant (`rds_iam` for
       PostgreSQL, the AWSAuthenticationPlugin for MySQL) and give it only the
       privileges the application needs.
    3. Remove shared application accounts and any account whose password is held in
       more than one place.
    4. Keep the master credential for break-glass only, held in Secrets Manager with
       rotation on.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '3.7'
  tag cis_rid:               '3.7'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0307r1_rule'
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
    its('clusters_without_iam_authentication') { should be_empty }
    its('clusters_without_iam_role_attached')  { should be_empty }
  end
end
