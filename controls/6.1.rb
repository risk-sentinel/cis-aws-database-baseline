# encoding: UTF-8

control 'C-6.1' do
  title 'Ensure Network Security is Enabled'
  desc  "
    Place the cluster in private subnets and restrict its security group to the
    cluster port from the application security group only.

    MemoryDB is a durable data store rather than a disposable cache, so exposure has
    the same consequence as exposing a database. Anything able to reach the port is
    positioned to read the data, which is why network placement is treated as a
    control in its own right rather than left to the default VPC.
  "
  desc  'rationale', "
    Place the cluster in private subnets and restrict its security group to the
    cluster port from the application security group only.

    MemoryDB is a durable data store rather than a disposable cache, so exposure has
    the same consequence as exposing a database. Anything able to reach the port is
    positioned to read the data, which is why network placement is treated as a
    control in its own right rather than left to the default VPC.
  "
  desc  'check', "
    1. Create or Select a Virtual Private Cloud (VPC)
    - Sign in to the AWS Management Console and open the Amazon VPC console at https://console.aws.amazon.com/vpc/.
    - Create a new VPC or select an existing VPC where you want to deploy your Amazon MemoryDB clusters.

    2. Configure Subnets
    - In the VPC console, navigate to `Subnets` in the left-side menu.
    - Create or select the subnets within your VPC where you want to deploy your Amazon MemoryDB clusters.
    - Ensure you have private subnets to isolate your MemoryDB clusters from the public internet.

    3. Define Security Groups
    - In the VPC console, navigate to `Security Groups` in the left-side menu.
    - Create a new security group or select an existing one for your Amazon MemoryDB clusters.
    - Configure inbound and outbound rules in the security group to control traffic access.
    	- Allow inbound access only from trusted sources, such as specific IP ranges or security groups, on the necessary ports used by MemoryDB.
    	- Define outbound rules based on your requirements, allowing outbound traffic to necessary destinations or ports.
    - Associate the security group with your Amazon MemoryDB clusters.

    4. Configure Network Access Control Lists (ACLs)
    - In the VPC console, navigate to `Network ACLs` in the left-side menu.
    - Create or select the network ACLs associated with the subnets used by your Amazon MemoryDB clusters.
    - Configure inbound and outbound rules in the network ACLs to control traffic access.
    	- Define rules based on your security requirements, allowing only necessary protocols, ports, and IP ranges.
    	- Deny unnecessary or unwanted traffic.
    - Associate the network ACLs with the subnets used by your Amazon MemoryDB clusters.

    5. Configure VPC Endpoints
    - In the VPC console, navigate to `Endpoints` in the left-side menu.
    - Create or select the VPC endpoints required for Amazon MemoryDB.
    	- If you need to access MemoryDB from within your VPC, create a VPC endpoint for Amazon MemoryDB to connect your applications securely.
    	- If you need to access MemoryDB from another VPC or on-premises network, set up VPC peering or a transit gateway to establish a secure connection.

    6. Verify Connectivity and Test
    - Launch an Amazon EC2 instance within the same VPC and subnet as your Amazon MemoryDB clusters or use an existing one.
    - Connect to the EC2 instance using SSH or other remote access methods.
    - Test the connectivity to your Amazon MemoryDB clusters by trying to connect to them using the appropriate client or utility.
    - Verify that the network security settings allow the necessary traffic and deny unauthorized access.
  "
  desc  'fix', "
    1. Place the cluster in a subnet group made of private subnets across at least
       two Availability Zones.
    2. Restrict the cluster security group to the MemoryDB port from the application
       security group only, and remove any broad CIDR rule.
    3. Confirm the subnets have no route to an internet gateway.
    4. MemoryDB is a durable data store rather than a cache - treat its network
       exposure with the same seriousness as a database, not a disposable tier.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SA-8']
  tag ksi:                   ['KSI-PIY-RSD']
  tag nist_r4:               ['SA-8']
  tag cci:                   ['CCI-000664']
  tag cis_number:            '6.1'
  tag cis_rid:               '6.1'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0601r1_rule'
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
      its('clusters_in_default_vpc') { should be_empty }
    end
  end
end
