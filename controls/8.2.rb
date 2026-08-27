# encoding: UTF-8

control 'C-8.2' do
  title 'Ensure Network Security is Enabled'
  desc  "
    In order to access Amazon Keyspaces the user is required to set specific networking parameters and security measurements without these extra steps they will not be able to access it. Users are required to create or select a virtual private cloud (VPC) and define their inbound and outbound rules accordingly.
  "
  desc  'rationale', "
    In order to access Amazon Keyspaces the user is required to set specific networking parameters and security measurements without these extra steps they will not be able to access it. Users are required to create or select a virtual private cloud (VPC) and define their inbound and outbound rules accordingly.
  "
  desc  'check', "
    1. Create or Select a Virtual Private Cloud (VPC)
    - Sign in to the AWS Management Console and open the Amazon VPC console at https://console.aws.amazon.com/vpc/.
    - Create a new VPC or select an existing VPC where you want to deploy your Amazon Keyspaces resources.

    2. Configure Subnets
    - In the VPC console, navigate to `Subnets` in the left-side menu.
    - Create or select the subnets within your VPC where you want to deploy your Amazon Keyspaces resources.
    - Ensure you have private subnets to isolate your Keyspaces resources from the public internet.

    3. Define Security Groups
    - In the VPC console, navigate to `Security Groups` in the left-side menu.
    - Create a new security group or select an existing one for your Amazon Keyspaces resources.
    - Configure inbound and outbound rules in the security group to control traffic access.
    	- Allow inbound access only from trusted sources, such as specific IP ranges or security groups, on the necessary ports used by Amazon Keyspaces.
    	- Define outbound rules based on your requirements, allowing outbound traffic to necessary destinations or ports.
    - Associate the security group with your Amazon Keyspaces resources.

    4. Configure Network Access Control Lists (ACLs)
    - In the VPC console, navigate to `Network ACLs` in the left-side menu.
    - Create or select the network ACLs associated with the subnets used by your Amazon Keyspaces resources.
    - Configure inbound and outbound rules in the network ACLs to control traffic access.
    	- Define rules based on your security requirements, allowing only necessary protocols, ports, and IP ranges.
    	- list text hereDeny unnecessary or unwanted traffic.
    - Associate the network ACLs with the subnets used by your Amazon Keyspaces resources.

    5. Configure VPC Endpoints
    - In the VPC console, navigate to `Endpoints` in the left-side menu.
    - Create or select the VPC endpoints required for Amazon Keyspaces.
    - If you need to access Keyspaces from within your VPC, create a VPC endpoint for Amazon Keyspaces to connect your applications securely.
    - If you need to access Keyspaces from another VPC or on-premises network, set up VPC peering or a transit gateway to establish a secure connection.

    6. Verify Connectivity and Test
    - Launch an Amazon EC2 instance within the same VPC and subnet as your Amazon Keyspaces resources or use an existing one.
    - Connect to the EC2 instance using SSH or other remote access methods.
    - Test the connectivity to your Amazon Keyspaces resources by trying to connect to them using the appropriate client or utility.
    - Verify that the network security settings allow the necessary traffic and deny unauthorized access.
  "
  desc  'fix', "
    Keyspaces is a regional endpoint service. Reach it privately rather than over
    the internet.

        ```
        aws ec2 create-vpc-endpoint --vpc-id <vpc-id> --vpc-endpoint-type Interface --service-name com.amazonaws.<region>.cassandra --subnet-ids <subnet-id> --security-group-ids <sg-id>
        ```

    1. Attach a security group to the endpoint permitting TCP 9142 from the client
       security group only.
    2. Apply an endpoint policy naming the keyspaces reachable through it.
    3. Add an `aws:SourceVpce` condition to the IAM policy where access should only
       be possible from inside the VPC.
  "
  tag severity:              'medium'
  tag nist:                  ['SA-8']
  tag cci:                   ['CCI-000664']
  tag cis_number:            '8.2'
  tag cis_rid:               '8.2'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0802r1_rule'
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
      its('regions_without_keyspaces_endpoint') { should be_empty }
    end
  end
end
