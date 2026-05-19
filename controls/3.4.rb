# encoding: UTF-8

control 'C-3.4' do
  title 'Ensure to Configure Security Groups'
  desc  "
    Configuring security groups benefits the user because it helps manage networks within the database and gives only certain permission for traffic that leaves and enters the database.
  "
  desc  'rationale', "
    Configuring security groups benefits the user because it helps manage networks within the database and gives only certain permission for traffic that leaves and enters the database.
  "
  desc  'check', "
    1. Sign into the AWS Management Console 
    - Sign into the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon RDS Console 
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/rds/.

    3. Select the RDS Instance 
    - Choose the Amazon RDS instance for which you want to configure security groups. Click on the instance name to access its details page.

    4. Navigate to the `Connectivity & Security` Section
    - In the instance details page, navigate to the `Connectivity & Security` or \"Security\" section.

    5. View and Modify Existing Security Groups
    - Under the `Security` section, you will see the existing security groups associated with the RDS instance.
    - Take note of the existing security groups and their inbound and outbound rules.

    6. Create a New Security Group
    - If you need to create a new security group for the RDS instance
    - Click the `Create New Security Group` button.
    - Provide a name and description for the new security group.
    - Configure the inbound and outbound rules to control network traffic to and from the RDS instance.
    - Click \"Create\" to create the new security group.

    7. Modify Security Group Rules
    - To modify the rules of an existing security group, click on the security group name or the `Modify` button next to it.
    - You can add, edit, or delete inbound and outbound rules on the security group details page.
    - Specify each rule's source IP addresses, port ranges, and protocols.
    - Click `Save` or `Apply Changes` to update the security group rules.

    8. Associate Security Groups
    - To associate a security group with the RDS instance, navigate to the `Connectivity & Security` or `Security` section of the instance details page.
    - Click `Modify` next to the `VPC security groups` option.
    - Select the desired security groups from the list.
    - Click `Save` or `Apply Changes` to associate them with the RDS instance.

    9. Verify and Test Security Group Configuration
    - Review the security group settings to match your network access requirements.
    - Test the connectivity to the RDS instance by attempting to access it from authorized IP addresses or applications.

    10. Monitor and Update Security Groups
    - Regularly monitor the network traffic and access patterns to your RDS instance.
    - Update the security group rules as needed to reflect changes in your network access requirements.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '3.4'
  tag cis_rid:               '3.4'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0304r1_rule'
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

  # Same technical bar as CIS 2.1 — CIS v2.0 revisits the check at the
  # generic-RDS level. Real describe in both places keeps the evidence
  # trail complete for consumers running either section.
  allowed_engines = Array(input('rds_engines'))

  aws_rds_instances.entries.each do |i|
    next unless allowed_engines.empty? || allowed_engines.include?(i[:engine])

    describe aws_rds_instance(db_instance_identifier: i[:db_instance_identifier]) do
      its('vpc_security_groups') { should_not be_empty }
    end
  end
end
