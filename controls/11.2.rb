# encoding: UTF-8

control 'C-11.2' do
  title 'Ensure Network Access is Secure'
  desc  "
    By applying certain network access such as Virtual Private Cloud (VPC) it protects the private network that has been established from any external networks from interfering. It allows internal networks to communicate with one another with the network that has been established. The Access Control List (ACLs) allows only specific individuals to access the resources. Also, by monitoring and logging the activity within the database it helps the individual know what is being logged within the activity and determine what next step they should take to address it.
  "
  desc  'rationale', "
    By applying certain network access such as Virtual Private Cloud (VPC) it protects the private network that has been established from any external networks from interfering. It allows internal networks to communicate with one another with the network that has been established. The Access Control List (ACLs) allows only specific individuals to access the resources. Also, by monitoring and logging the activity within the database it helps the individual know what is being logged within the activity and determine what next step they should take to address it.
  "
  desc  'check', "
    1. Deploy QLDB in a VPC
    - Create a Virtual Private Cloud (VPC) to isolate your QLDB resources.
    - Define the network CIDR blocks, subnets, and routing configurations for the VPC.
    - Ensure that the VPC is correctly configured with appropriate network access controls.

    2. Configure Security Groups
    - Create security groups within your VPC to control inbound and outbound traffic to QLDB.
    - Determine the necessary protocols and ports for QLDB access.
    - Configure security group rules to allow access from trusted sources, such as specific IP ranges or other security groups within your VPC.

    3. Set Up Network ACLs
    - Configure Network Access Control Lists (ACLs) within your VPC to provide an additional layer of network security.
    - Define inbound and outbound rules in the ACLs to allow or deny specific traffic based on IP addresses, ports, or protocols.
    - Review and adjust the ACL rules to align with your organization's security policies and requirements.

    4. Use VPC Endpoints or PrivateLink
    - Consider using VPC endpoints or AWS PrivateLink to securely access QLDB without traversing the public internet.
    - Set up a VPC endpoint for QLDB to allow private connectivity within your VPC.
    - Configure the routing and security group rules to enable traffic flow through the VPC endpoint or PrivateLink.

    5. Secure External Connections
    - If external connections to QLDB are required, implement secure access methods such as Virtual Private Network (VPN) or AWS Direct Connect.
    - Configure VPN connections or Direct Connect links to establish encrypted and private connectivity between your on-premises network and the VPC hosting QLDB.
    - Apply appropriate security measures, such as strong authentication and encryption, to protect data transmitted over external connections.

    6. Enable Logging and Monitoring
    - Enable logging for QLDB to capture important system events and database activity.
    - Utilize services like Amazon CloudWatch Logs to centralize and analyze QLDB logs.
    - Set up appropriate alarms and notifications to alert you of any suspicious network activity or potential security incidents.

    7. Regularly Review and Update Network Security
    - Regularly review your VPC configurations, security groups, and network ACLs.
    - Stay informed about AWS security best practices and recommendations.
    - Update your network security measures as needed to address emerging threats or changes in your security requirements.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['SA-8']
  tag cci:                   ['CCI-000664']
  tag cis_number:            '11.2'
  tag cis_rid:               '11.2'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-1102r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('redshift')
  # Hoisted so an EMPTY collection is a declared state rather than an absent one.
  # The service can be in scope while the account holds none of the resource: the
  # loop below then never executed, the control registered no describe blocks, and
  # it emitted ZERO results — neither passed nor Not Applicable, just absent. A
  # control that asserts nothing while reporting not-red is the failure this
  # profile exists to catch, and it also fails `hdf convert`, whose schema requires
  # at least one result per requirement.
  scoped_items = aws_redshift_clusters.cluster_identifiers
  applicable           = applicable_partition && applicable_service && !scoped_items.empty?

  impact 0.5
  impact 0.0 unless applicable

  only_if("REDSHIFT out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')}) or none present in this account") do
    applicable
  end

  scoped_items.each do |id|
    describe aws_redshift_cluster(cluster_identifier: id) do
      its('publicly_accessible')   { should eq false }
      its('vpc_security_group_ids') { should_not be_empty }
    end
  end
end
