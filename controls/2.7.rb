# encoding: UTF-8

control 'C-2.7' do
  title 'Ensure Least Privilege Access'
  desc  "
    Use the principle of least privilege when granting access to your Amazon Aurora resources. This principle of least privilege (POLP) is a computer security concept where users are given the minimum access levels necessary to complete their job functions. 

    In Amazon Aurora, this can be implemented at various levels, including AWS IAM for managing AWS resources and within the database for managing database users and roles.

    Here is a step-by-step guide for each:

    POLP limits the user interaction on the database, and it only gives the database permission to complete the necessary or mandatory task. AWS IAM gives permission for what the entity can and cannot do. Incorporating both POLP and AWS IAM in a database gives limited permission to the user to complete the tasks.
  "
  desc  'rationale', "
    Use the principle of least privilege when granting access to your Amazon Aurora resources. This principle of least privilege (POLP) is a computer security concept where users are given the minimum access levels necessary to complete their job functions. 

    In Amazon Aurora, this can be implemented at various levels, including AWS IAM for managing AWS resources and within the database for managing database users and roles.

    Here is a step-by-step guide for each:

    POLP limits the user interaction on the database, and it only gives the database permission to complete the necessary or mandatory task. AWS IAM gives permission for what the entity can and cannot do. Incorporating both POLP and AWS IAM in a database gives limited permission to the user to complete the tasks.
  "
  desc  'check', "
    Implementing POLP with AWS IAM

    1. Sign in to AWS Management Console 
    - If you do not already have an AWS account, you will need to create one at https://aws.amazon.com.

    2. Navigate to IAM Dashboard 
    - Navigate to the IAM service once logged in to the AWS Management Console. 
    - You can find this under the `Security, Identity, & Compliance` category.

    3. Create a new IAM role or user
    - If creating a new IAM role or user, click `Roles` or `Users`.
    - Then `Create role` or `Create user`.

    4. Attach minimum necessary permissions 
    - When attaching policies, give only the permissions necessary to perform the intended tasks. 
    - AWS provides many predefined policies designed following the POLP. You can create a custom policy with precise - permissions if none suits your needs.

    Implementing POLP within Amazon Aurora
    1. Log into your Aurora Database 
    Depending on your Aurora database engine, you can log in through the terminal using a MySQL or PostgreSQL client. 
    You'll need your host endpoint, username, and password to log in.
    2. Create a new user 
    You can create a new user with the CREATE USER command in SQL. 

    For example,
    ```
    CREATE USER ' '@' ' IDENTIFIED BY 'password';
    ```
    3. Grant minimal necessary privileges 
    After creating the user, you can grant privileges using the GRANT command. 
    The privileges should be as limited as possible for the user to perform their necessary functions. 

    For example,
    ```
    GRANT SELECT, INSERT ON TO ' '@' ';
    ```
    4. Regularly review permissions
    It is essential to regularly review and update permissions to make sure they adhere to the principle of least privilege. 
    You can view a user's permissions with the SHOW GRANTS command; for example,
    ```
    SHOW GRANTS FOR ' '@' ';
    ```
  "
  desc  'fix', "
    This is important because it reduces and secures any possible threat that an unauthorized user can gain by hacking into the system.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '2.7'
  tag cis_rid:               '2.7'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0207r1_rule'
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
    its('clusters_without_iam_role_attached') { should be_empty }
    its('clusters_with_default_master_username') { should be_empty }
  end
end
