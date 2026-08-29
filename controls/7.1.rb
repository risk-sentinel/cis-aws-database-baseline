# encoding: UTF-8

control 'C-7.1' do
  title 'Ensure Network Architecture Planning'
  desc  "
    Plan the network architecture to isolate your DocumentDB instances within a secure Virtual Private Cloud (VPC). Configure appropriate security groups and network access control lists (ACLs) to control inbound and outbound traffic to your DocumentDB instances.

    Depending on how the network is established between devices, which then helps secure data when transferring it from one server to another.
  "
  desc  'rationale', "
    Plan the network architecture to isolate your DocumentDB instances within a secure Virtual Private Cloud (VPC). Configure appropriate security groups and network access control lists (ACLs) to control inbound and outbound traffic to your DocumentDB instances.

    Depending on how the network is established between devices, which then helps secure data when transferring it from one server to another.
  "
  desc  'check', "
    1. Understand Amazon VPC Basics
    - Familiarize yourself with Amazon Virtual Private Cloud (VPC) and its concepts.
    - Learn about VPC components, including subnets, route tables, and security groups.

    2. Determine VPC Requirements for DocumentDB
    - Identify the specific networking requirements for your Amazon DocumentDB deployment.
    - Consider factors such as network availability, fault tolerance, and security requirements.

    3. Create a New VPC or Use an Existing VPC
    - Decide whether to create a new VPC dedicated to Amazon DocumentDB or use an existing VPC.
    - If creating a new VPC, follow the steps to create a VPC in the AWS Management Console.

    4. Configure Subnets
    - Determine the number and size of subnets needed for your DocumentDB deployment.
    - Create the required subnets within your VPC, ensuring proper availability zone distribution.

    5. Set Up Routing
    - Configure the route tables associated with your subnets.
    - Ensure that the route tables have the necessary routes for proper network connectivity.

    6. Configure Security Groups
    - Create or configure security groups to control inbound and outbound traffic to your DocumentDB instances.
    - Define the necessary inbound rules to allow access from authorized sources.

    7. Plan Connectivity Options
    - Decide how your DocumentDB instances will connect to your VPC and other resources.
    - Determine if you need to set up VPC peering, VPN connections, or AWS Direct Connect for connectivity.

    8. Consider High Availability and Fault Tolerance
    - Evaluate your requirements for high availability and fault tolerance.
    - Design your network architecture to ensure that DocumentDB instances are deployed across multiple availability zones for resilience.

    9. Implement Network Access Control
    - Consider using network access control lists (ACLs) to provide an additional layer of security.
    - Configure the ACLs to allow only necessary traffic and block unauthorized access.

    10. Test and Validate the Network Architecture
    - Ensure that your network architecture is correctly configured and meets your requirements.
    - Test connectivity and verify that DocumentDB instances can be accessed securely.
  "
  desc  'fix', "
    To establish connection, the users would need to factor in their virtual private cloud (VPC), create subnet, configure routing, and implement ACLs.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SA-8']
  tag nist_r4:               ['SA-8']
  tag cci:                   ['CCI-000664']
  tag cis_number:            '7.1'
  tag cis_rid:               '7.1'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0701r1_rule'
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
    its('clusters_in_default_vpc') { should be_empty }
  end
end
