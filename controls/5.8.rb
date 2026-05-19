# encoding: UTF-8

control 'C-5.8' do
  title 'Ensure Authentication and Access Control is Enabled'
  desc  "
    Individual creates IAM roles that would give specific permission to what the user can and cannot do within that database. The Access Control List (ACLs) allows only specific individuals to access the resources.
  "
  desc  'rationale', "
    Individual creates IAM roles that would give specific permission to what the user can and cannot do within that database. The Access Control List (ACLs) allows only specific individuals to access the resources.
  "
  desc  'check', "
    1. Sign in to the AWS Management Console
    - Sign in to the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon Keyspaces Console
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/keyspaces/.

    3. Select the Keyspace
    - Choose the Keyspace (database) for which you want to implement authentication and access control. 
    - Click on the Keyspace name to access its details page.

    4. Enable IAM for Cassandra
    - In the Keyspace details page, click on the `Configuration` tab.
    - Under the `Authentication and access control` section, locate the \"IAM for Cassandra\" option.
    - Click on `Edit`.
    - Select the `Enable` option to enable IAM for Cassandra authentication and authorization.
    - Choose the IAM role(s) that can access the Keyspace
    - Click `Save` to enable IAM for Cassandra.

    5. Define IAM Roles and Permissions
    - Open the IAM console by navigating to `Identity and Access Management (IAM)` in the AWS Management Console.
    - Create IAM roles with appropriate policies defining the desired access level to your Amazon Keyspaces resources.
    - You may create different roles for different user groups or applications.
    - Ensure that the IAM policies associated with these roles allow the necessary permissions for interacting with Keyspaces.
    - Attach the IAM roles to the appropriate AWS identities, such as IAM users or AWS Identity and Access Management roles.

    6. Review and Update Access Control
    - In the Keyspace details page, click on the `Configuration` tab.
    - Under the `Authentication and access control` section, click on `Access Control Lists` (ACLs).
    - Review the ACLs to define fine-grained access control at the table and row level.
    	- Define rules that allow or deny access based on specific conditions, such as IP addresses or IAM roles.
    	- Ensure that the ACL rules align with your security requirements and restrict access to sensitive data if necessary.
    - Update the ACLs as needed to accommodate changes.

    7. Verify Authentication and Access Control
    - Test the authentication and access control mechanisms using client applications or tools that connect to your Amazon Keyspaces resources.
    - Verify that only authorized users or applications can access the Keyspaces resources based on the defined IAM roles and ACL rules.
    - Monitor the access logs and perform periodic reviews to ensure the authentication and access control measures function as intended.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '5.8'
  tag cis_rid:               '5.8'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0508r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('elasticache')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("ELASTICACHE out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  aws_elasticache_clusters.ids.each do |id|
    describe aws_elasticache_cluster(cache_cluster_id: id) do
      its('auth_token_enabled') { should eq true }
    end
  end
end
