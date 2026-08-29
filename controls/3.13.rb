# encoding: UTF-8

control 'C-3.13' do
  title 'Ensure Database has IAM Auth is Enabled'
  desc  "
    RDS clusters should be configured to leverage AWS IAM authentication for database connections. This ensures that users authenticate using temporary IAM-based tokens rather than static long-lived passwords.

    Enabling IAM authentication for RDS centralizes and strengthens access control by integrating database authentication with broader AWS IAM identity management. This approach eliminates the risks associated with hard-coded credentials, reduces administrative overhead for password rotation, and allows precise access management using IAM identities and policies.
  "
  desc  'rationale', "
    RDS clusters should be configured to leverage AWS IAM authentication for database connections. This ensures that users authenticate using temporary IAM-based tokens rather than static long-lived passwords.

    Enabling IAM authentication for RDS centralizes and strengthens access control by integrating database authentication with broader AWS IAM identity management. This approach eliminates the risks associated with hard-coded credentials, reduces administrative overhead for password rotation, and allows precise access management using IAM identities and policies.
  "
  desc  'check', "
    1. List RDS clusters and check IAM authentication status:
    ```
    aws rds describe-db-clusters \\
      --query \"DBClusters[*].{DBClusterIdentifier:DBClusterIdentifier,IAMDatabaseAuthenticationEnabled:IAMDatabaseAuthenticationEnabled}\" \\
      --output table
    ```

    2. List database users enabled for IAM authentication (RDS MySQL):

    - For MySQL, connect to the cluster and run below command to ensure that required database users exist for IAM token logins.

    ```
    SELECT user, plugin FROM mysql.user WHERE plugin='AWSAuthenticationPlugin';
    ```

    - For Postgres, connect to the cluster and run below command to verify that necessary users are granted the rds_iam role.

    ```
    SELECT r.rolname
    FROM pg_roles AS r
    JOIN pg_auth_members AS m ON r.oid = m.member
    JOIN pg_roles AS g ON m.roleid = g.oid
    WHERE g.rolname = 'rds_iam';
    ```

    The cluster must have IAM database authentication enabled and users intended for IAM authentication must exist in the database engine with appropriate privileges.
  "
  desc  'fix', "
    1. Enable IAM Database Authentication on the RDS Cluster

    - Use the AWS CLI to enable IAM authentication for an existing RDS cluster:

    ```
    aws rds modify-db-cluster \\
      --db-cluster-identifier \\
      --enable-iam-database-authentication \\
      --apply-immediately
    ```

    2. Create Local Database Users Configured for IAM Authentication

    - For RDS MySQL: Connect to the database and create or alter users as follows:

    ```
    CREATE USER 'jane_doe' IDENTIFIED WITH AWSAuthenticationPlugin as 'RDS';
    ```

    or

    ```
    ALTER USER 'jane_doe' IDENTIFIED WITH AWSAuthenticationPlugin as 'RDS';
    ```

    - For RDS PostgreSQL:
    Grant the rds_iam role to eligible users:

    ```
    GRANT rds_iam TO jane_doe;
    ```

    3. Grant Necessary Privileges to the Database Users
    - Assign required permissions and roles to the users within your DB engine via standard SQL GRANT commands.

    4. Ensure IAM Users/Roles Have Required AWS Permissions
    - The IAM principal that connects needs the following AWS permission in their policy:

    ```
    {
        \"Version\":\"2012-10-17\",		 	 	 
        \"Statement\": [
            {
                \"Effect\": \"Allow\",
                \"Action\": [
                    \"rds-db:connect\"
                ],
                \"Resource\": [
                    \"arn:aws:rds-db:region:account-id:dbuser:DbClusterResourceId/db-user-name\"
                ]
            }
        ]
    }
    ```
    - region is the AWS Region for the DB cluster
    - account-id is the AWS account number for the DB cluster.
    - DbClusterResourceId is the identifier for the DB cluster. This identifier is unique to an AWS Region and never changes. To find a DB cluster resource ID in the AWS Management Console for Amazon RDS, choose the DB cluster to see its details. Then choose the Configuration tab. The Resource ID is shown in the Configuration section.

    5. Test the Configuration

    - Use the AWS CLI to generate an authentication token:

    ```
    aws rds generate-db-auth-token \\
      --hostname \\
      --port 3306 \\
      --region \\
      --username ```

    - Use the generated token to authenticate to the database, confirming successful login.

    For mysql:

    ```
    mysql --host= \\
      --port=3306 \\
      --ssl-mode=REQUIRED \\
      --enable-cleartext-plugin \\
      --user= \\
      --password= ' '
    ```

    For postgres:

    ```
    psql \"host= port=5432 dbname= user=<>db_user_name password=' ' sslmode=require\"
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 (2)']
  tag nist_r4:               ['AC-2 (2)']
  tag cci:                   ['CCI-001682']
  tag cis_number:            '3.13'
  tag cis_rid:               '3.13'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0313r1_rule'
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

  # Same technical bar as CIS 2.10 — redundant coverage by design.
  allowed_engines = Array(input('rds_engines'))

  scoped_items.each do |c|
    next unless allowed_engines.empty? || allowed_engines.include?(c[:engine])

    describe aws_rds_cluster(db_cluster_identifier: c[:db_cluster_identifier]) do
      its('iam_database_authentication_enabled') { should eq true }
    end
  end
end
