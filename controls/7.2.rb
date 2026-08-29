# encoding: UTF-8

control 'C-7.2' do
  title 'Ensure VPC Security is Configured'
  desc  "
    Creating a VPC, configuring subnets, and creating security groups help isolate your DocumentDB instances within your virtual network and control inbound and outbound traffic.

    Setting up a Virtual Private Cloud (VPC) protects the private network that has been established from any external networks from interfering. It allows internal networks to communicate with one another with the network that has been established.
  "
  desc  'rationale', "
    Creating a VPC, configuring subnets, and creating security groups help isolate your DocumentDB instances within your virtual network and control inbound and outbound traffic.

    Setting up a Virtual Private Cloud (VPC) protects the private network that has been established from any external networks from interfering. It allows internal networks to communicate with one another with the network that has been established.
  "
  desc  'check', "
    1. Sign into the AWS Management Console
    - Sign into the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon VPC Console
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/vpc/.

    3. Create a VPC (Virtual Private Cloud)
    - Click on the `Create VPC` button to create a new VPC.
    - Provide the necessary details, such as VPC name, CIDR block, and additional configuration options.
    - Click on `Create` to create the VPC.

    4. Configure VPC Subnets
    - Once the VPC is created, navigate to the `Subnets` section in the VPC console.
    - Click on the `Create subnet` button to create a new subnet.
    - Provide the necessary details, such as subnet name, VPC selection, and subnet CIDR block.
    - Repeat this step to create multiple subnets within your VPC, if required.

    5. Create Security Groups
    - Navigate to the `Security Groups` section in the VPC console.
    - Click the `Create security group` button to create a new security group.
    - Provide a name and description for the security group.
    - Configure inbound and outbound rules to allow the necessary traffic to and from the DocumentDB instances.
    - Repeat this step to create additional security groups if needed.

    6. Launch Amazon DocumentDB Cluster in VPC
    - Navigate to the service using the \"Find Services\" search bar or by directly accessing the console at https://console.aws.amazon.com/docdb/.
    - Click on `Create database` to create a new DocumentDB cluster.
    - Configure the necessary parameters, such as cluster name, instance specifications, and storage options.
    - In the `Network & Security` section, select the VPC and subnets you created earlier.
    - Choose the appropriate security group(s) to apply to the DocumentDB cluster.
    - Click `Create` to launch the DocumentDB cluster in the configured VPC.

    7. Test Connectivity
    - Once the DocumentDB cluster is launched, validate that you can connect to it from authorized sources.
    - Use the appropriate database client or tools to establish a connection and verify connectivity.

    8. Monitor and Update Security Groups
    - Regularly monitor and update the security groups associated with the DocumentDB cluster.
    - Modify the inbound and outbound rules to ensure appropriate access control and security.
  "
  desc  'fix', "
    The individual is required to create a subnet and configure their inbound and outbound access. Individuals are supposed to configure and route, ensuring the traffic is flowing smoothly without any interference. This control is important because it only allows authorized users to access their resources as they prefer.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SA-8']
  tag ksi:                   ['KSI-PIY-RSD']
  tag nist_r4:               ['SA-8']
  tag cci:                   ['CCI-000664']
  tag cis_number:            '7.2'
  tag cis_rid:               '7.2'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0702r1_rule'
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
    its('clusters_with_open_security_groups') { should be_empty }
  end
end
