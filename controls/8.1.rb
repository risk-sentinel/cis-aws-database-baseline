# encoding: UTF-8

control 'C-8.1' do
  title 'Ensure Keyspace Security is Configured'
  desc  "
    To access Amazon Keyspaces, the user would be required to log in with their AWS credentials. Once logged in the user can access the AWS resources and can explore the resources that Amazon Keyspaces offers. Amazon Keyspaces offers a lot of security that can mitigate a potential attack.
  "
  desc  'rationale', "
    To access Amazon Keyspaces, the user would be required to log in with their AWS credentials. Once logged in the user can access the AWS resources and can explore the resources that Amazon Keyspaces offers. Amazon Keyspaces offers a lot of security that can mitigate a potential attack.
  "
  desc  'check', "
    1. Sign in to the AWS Management Console
    - Sign in to the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon Keyspaces Console
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/keyspaces/.

    3. Explore Amazon Keyspaces Security Features
    - In the Amazon Keyspaces console, navigate to the `Features` or `Security` section to explore the available security features.
    - Take note of the following critical security features:
    	- Encryption at Rest: Understand how Amazon Keyspaces provides encryption at rest for your data. It uses server-side encryption by default, ensuring that data stored in Keyspaces is encrypted.
    	- Encryption in Transit: Learn how to configure encryption in transit for data transmitted between your client applications and Amazon Keyspaces. Amazon Keyspaces supports Transport Layer Security (TLS) encryption to secure the communication channel.
    	- Virtual Private Cloud (VPC) Support: Explore the VPC support options Amazon Keyspaces provides. It allows you to deploy your Keyspaces resources within your VPC for enhanced network isolation and control.
    	- Authentication Options: Understand the authentication mechanisms available in Amazon Keyspaces. IAM for Cassandra allows you to use AWS Identity and Access Management (IAM) to authenticate and authorize client connections to Keyspaces.
    	- Access Control: Learn about access control options in Amazon Keyspaces. It supports fine-grained access control using Access Control Lists (ACLs) at the table and row level to manage access permissions for different users or roles.
    	- Audit Logging: Explore how to enable audit logging for Amazon Keyspaces. Amazon CloudWatch Logs can capture and store logs from your Keyspaces resources, providing visibility into activities for security and compliance purposes.

    4. Documentation and Resources
    - Access the official Amazon Keyspaces documentation by navigating to the `Documentation` or `Learn` section in the Amazon Keyspaces console.
    - Review the comprehensive documentation to gain in-depth knowledge about each security feature, including best practices, configuration options, and implementation details.
    - Utilize other AWS resources such as whitepapers, blogs, and security-related documentation further to enhance your understanding of Amazon Keyspaces security features.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '8.1'
  tag cis_rid:               '8.1'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0801r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('keyspaces')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("KEYSPACES out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  inv = aws_keyspaces_compliance(regions: input('scan_regions'))
  if inv.connection_error
    describe 'Amazon Keyspaces inventory' do
      skip "Requires manual review and attestation provided for this control (#{inv.connection_error})"
    end
  else
    describe inv do
      its('tables_without_encryption') { should be_empty }
    end
  end
end
