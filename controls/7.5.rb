# encoding: UTF-8

control 'C-7.5' do
  title 'Ensure to Implement Access Control and Authentication'
  desc  "
    Configure authentication mechanisms for your DocumentDB instances, such as using AWS Identity and Access Management (IAM) users or database users. Define appropriate user roles and permissions to control access to the DocumentDB instances and databases.
  "
  desc  'rationale', "
    Configure authentication mechanisms for your DocumentDB instances, such as using AWS Identity and Access Management (IAM) users or database users. Define appropriate user roles and permissions to control access to the DocumentDB instances and databases.
  "
  desc  'check', "
    1. Sign into the AWS Management Console
    - Sign into the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon DocumentDB Console
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/docdb/.

    3. Select the DocumentDB Cluster
    - Choose the Amazon DocumentDB cluster for which you want to implement access control and authentication. 
    - Click on the cluster name to access its details page.
    - In the cluster details page, navigate to the \"Configuration\" section.

    4. Enable Authentication
    - Under the `Network & Security` section.
    - Click on the `Edit` button or `Modify` option to configure the authentication settings.
    - Enable the option for authentication by choosing the appropriate setting.
    - DocumentDB supports authentication through username and password or through AWS Identity and Access Management (IAM) roles.

    5. Configure Database Users
    - In the cluster details page, navigate to the `Users` or `Database users` section.
    - Click the `Add user` button to create a new database user.
    - Enter the username and password for the database user.
    - Assign appropriate permissions to the user, such as read-only or read-write access to specific databases or collections.

    6. Save the Configuration
    - Click on the `Save` button to apply the authentication and access control configuration.
    - DocumentDB will enforce authentication for connections to the cluster.

    7. Test Authentication
    - Validate that your client applications or tools can connect to the DocumentDB cluster using the configured authentication credentials.
    - Ensure that the authentication process is successfully completed.

    8. Monitor and Manage Access Control
    - Regularly monitor and manage the access control configuration for your DocumentDB cluster.
    - Review and update the permissions assigned to database users as needed.
    - Remove any unnecessary or unused database users to minimize security risks.

    9. Consider IAM Authentication (Optional)
    - If desired, you can also configure IAM authentication for your DocumentDB cluster.
    - Follow the AWS documentation to set up IAM authentication for DocumentDB, if applicable.
  "
  desc  'fix', "
    1. Create a database user per application with only the roles it needs, rather
       than sharing the cluster's master user.
    2. Hold credentials in Secrets Manager with rotation enabled:

        ```
        aws secretsmanager rotate-secret --secret-id <secret-arn> --rotation-lambda-arn <lambda-arn> --rotation-rules AutomaticallyAfterDays=30
        ```

    3. Use built-in roles (`read`, `readWrite`) scoped to a specific database rather
       than `root` or `dbAdminAnyDatabase`.
    4. Keep the master credential for break-glass use, and alarm on its retrieval.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '7.5'
  tag cis_rid:               '7.5'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0705r1_rule'
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

  describe aws_rds_cluster_compliance(regions: input('scan_regions'), engines: ['docdb']) do
    its('clusters_without_iam_authentication') { should be_empty }
  end
end
