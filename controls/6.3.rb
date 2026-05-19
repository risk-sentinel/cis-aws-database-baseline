# encoding: UTF-8

control 'C-6.3' do
  title 'Ensure Authentication and Access Control is Enabled'
  desc  "
    Users should select whether they like to enable authentication. If they want to authenticate a password would be required, which would only allow the authorized person to access the cluster. Defining access control allows specific workers in a business access to the database.
  "
  desc  'rationale', "
    Users should select whether they like to enable authentication. If they want to authenticate a password would be required, which would only allow the authorized person to access the cluster. Defining access control allows specific workers in a business access to the database.
  "
  desc  'check', "
    1. Sign into the AWS Management Console
    - Sign into the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon MemoryDB Console
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/memorydb/.

    3. Select the Cluster
    - Choose the Amazon MemoryDB cluster on which you want to implement authentication and access control.
    - Click on the cluster name to access its details page.

    4. Enable Authentication
    - In the cluster details page, navigate to the `Authentication` section.
    - Click on `Modify` to edit the authentication settings.
    - Select the desired authentication option:
    	- No Authentication: This option allows unauthenticated access to your MemoryDB cluster.
    	- Password Authentication: Choose this option to enable password-based authentication. Enter the desired password for the cluster.
    - Click `Apply Changes` to enable authentication for the MemoryDB cluster.

    5. Define Access Control Policies
    - In the cluster details page, navigate to the \"Access Control\" section.
    - Click on `Modify` to edit the access control settings.
    - Define the access control policies based on your requirements:
    	- For Redis-based clusters, you can use Redis Access Control Lists (ACLs) to control access at the Redis command level.
    	- Use the Redis commands to create, modify, or delete ACL rules as needed.
    	- You can define rules based on IP addresses, users, or patterns to allow or deny specific commands or operations.
    - Click `Apply Changes` to save the access control policies for the MemoryDB cluster.

    6. Test Authentication and Access Control
    - Use a Redis client or utility to connect to your Amazon MemoryDB cluster.
    - Provide the necessary authentication credentials, such as the password, if password-based authentication is enabled.
    - Test the connection and verify that you can access the MemoryDB cluster based on the defined access control policies.

    7. Regularly Review and Update Access Control
    - Periodically review the access control policies to ensure they align with your security requirements.
    - Update the ACL rules, passwords, or other authentication mechanisms to adapt to changing access requirements or security policies.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '6.3'
  tag cis_rid:               '6.3'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0603r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('memorydb')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("MEMORYDB out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  inv = aws_memorydb_compliance(regions: input('scan_regions'))
  if inv.connection_error
    describe 'AWS MemoryDB inventory' do
      skip "Requires manual review and attestation provided for this control (#{inv.connection_error})"
    end
  else
    describe inv do
      its('clusters_with_open_access_acl') { should be_empty }
    end
  end
end
