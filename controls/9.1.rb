# encoding: UTF-8

control 'C-9.1' do
  title 'Ensure Network Security is Enabled'
  desc  "
    This helps ensure that all the necessary security measurements are taken to prevent a cyber-attack. Such as utilizing VPC, creating certain inbound and outbound rules, and ACLs.
  "
  desc  'rationale', "
    This helps ensure that all the necessary security measurements are taken to prevent a cyber-attack. Such as utilizing VPC, creating certain inbound and outbound rules, and ACLs.
  "
  desc  'check', "
    1. Sign in to the AWS Management Console 
    - Sign in to the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon Neptune Console 
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/neptune/.

    3. Select the Neptune Cluster 
    - Choose the Amazon Neptune cluster for which you want to configure network security. 
    - Click on the cluster name to access its details page.

    4. Configure Security Groups
    - In the cluster details page, navigate to the `Connectivity & Security` or `Network & Security` section.
    - Under `Security Groups`, click on `Manage security groups`.
    - Click on `Create new security group` or select an existing security group associated with your Neptune cluster.
    - Configure inbound and outbound rules within the security group to control network traffic.
    	- For inbound rules, specify the allowed source IP addresses or security groups and the necessary ports for accessing the Neptune cluster.
    	- For outbound rules, define the allowed destination IP addresses or security groups and the required ports for outbound connections from the Neptune cluster.
    - Save the security group settings.

    5. Configure Network Access Control Lists (ACLs)
    - In the cluster details page, navigate to the `Connectivity & Security` or `Network & Security` section.
    - Under `Network Access Control Lists (ACLs)`, click on `Manage network ACLs`.
    - Create a new network ACL or select an existing one associated with your Amazon Neptune cluster.
    - Configure inbound and outbound rules within the network ACL to control network traffic at the subnet level.
    - Define rules based on IP address ranges, protocols, and ports to allow or deny specific traffic.
    - Consider security best practices and compliance requirements when configuring the network ACL rules.
    - Save the network ACL settings.

    6. Verify Network Security Configuration
    - Review the security group and network ACL settings to ensure they align with your security requirements.
    - Confirm that the inbound and outbound rules only allow necessary traffic and deny unauthorized access.
    - Verify that your Neptune cluster's security groups and network ACLs are correctly configured.

    7. Test Network Connectivity
    - Launch an Amazon EC2 instance within the same VPC and subnet as your Neptune cluster, or use an existing one.
    - Connect to the EC2 instance using SSH or other remote access methods.
    - Test the network connectivity to your Neptune cluster by attempting to connect to it using the appropriate client or utility.
    - Ensure that the network security settings allow the necessary traffic and deny unauthorized access.
  "
  desc  'fix', "
    1. Place the cluster in a DB subnet group of private subnets across at least two
       Availability Zones.
    2. Restrict the cluster security group to TCP 8182 from the application security
       group only.
    3. Neptune has no public accessibility option - it is always VPC-only - so the
       exposure risk is a permissive security group or a peered network, not a public
       endpoint. Check both.
    4. Use an interface VPC endpoint for the management API so control-plane calls do
       not need internet egress.
  "
  tag severity:              'medium'
  tag nist:                  ['SA-8']
  tag cci:                   ['CCI-000664']
  tag cis_number:            '9.1'
  tag cis_rid:               '9.1'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0901r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('neptune')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("NEPTUNE out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe aws_rds_cluster_compliance(regions: input('scan_regions'), engines: ['neptune']) do
    its('clusters_with_open_security_groups') { should be_empty }
  end
end
