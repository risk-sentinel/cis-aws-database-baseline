# encoding: UTF-8

control 'C-3.3' do
  title 'Ensure to Create a Virtual Private Cloud (VPC)'
  desc  "
    Setting up a Virtual Private Cloud (VPC) protects the private network that has been established from any external networks from interfering. It allows internal networks to communicate with one another with the network that has been established.
  "
  desc  'rationale', "
    Setting up a Virtual Private Cloud (VPC) protects the private network that has been established from any external networks from interfering. It allows internal networks to communicate with one another with the network that has been established.
  "
  desc  'check', "
    1. Sign in to the AWS Management Console 
    - Sign in to the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon VPC Console
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/vpc/.

    3. Create a VPC
    - In the Amazon VPC console, click `Your VPCs` in the left-side menu.
    - Click on `Create VPC` to begin creating a new VPC.
    - Provide a name and the desired IPv4 CIDR block for your VPC.
    - Configure additional settings, such as IPv6 CIDR block, tenancy, and DNS resolution.
    - Click `Create` to create the VPC.

    4. Create Subnets
    - In the Amazon VPC console, click `Subnets` in the left-side menu.
    - Click on `Create subnet` to create a subnet within the VPC.
    - Select the VPC you created in the previous step.
    - Provide a name, choose an availability zone, and specify the IPv4 CIDR block for the subnet.
    - Configure additional settings, such as IPv6 CIDR block and availability zone.
    - Click `Create` to create the subnet.

    5. Configure Route Tables
    - In the Amazon VPC console, click on `Route Tables` in the left-side menu.
    - Click on `Create route table` to create a new route table.
    - Provide a name for the route table and select the VPC you created earlier.
    - Click `Create` to create the route table.
    - Associate the route table with the desired subnets by selecting the route table and clicking on the `Subnet associations` tab.
    - Click `Edit subnet associations` and select the desired subnets to associate them with the route table.

    6. Configure Security Groups
    - In the Amazon VPC console, click `Security Groups` in the left-side menu.
    - Click on `Create security group` to create a new security group.
    - Provide a name and description for the security group.
    - Select the VPC you created earlier.
    - Configure inbound and outbound rules to control network traffic to and from your RDS instances.
    - Click `Create` to create the security group.

    7. Configure Network Access Control Lists (ACLs) 
    - In the Amazon VPC console, click on `Network ACLs` in the left-side menu.
    - Click on `Create network ACL` to create a new network ACL.
    - Provide a name for the network ACL and select the VPC you created earlier.
    - Configure inbound and outbound rules to allow or deny specific types of traffic.
    - Associate the network ACL with the desired subnets by selecting the network ACL and clicking on the `Subnet associations` tab.
    - Click `Edit subnet associations` and select the desired subnets to associate them with the network ACL.

    8. Use the VPC with Amazon RDS
    - Select the appropriate VPC, subnets, and security groups when creating an RDS instance.
    - Configure the database instance with the desired network and security settings within the chosen VPC.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['SA-8']
  tag cci:                   ['CCI-000664']
  tag cis_number:            '3.3'
  tag cis_rid:               '3.3'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0303r1_rule'
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
    its('clusters_in_default_vpc') { should be_empty }
  end
end
