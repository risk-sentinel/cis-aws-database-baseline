# encoding: UTF-8

control 'C-5.2' do
  title 'Ensure Network Security is Enabled'
  desc  "
    Implementing network security for Amazon ElastiCache involves configuring your Virtual Private Cloud (VPC), security groups, and network access controls to control access to your ElastiCache clusters.

    This helps ensure that the data is safe and protected from any threats and or misconfigurations within the network. This helps to keep a potential hacker getting into the system and compromising the data.
  "
  desc  'rationale', "
    Implementing network security for Amazon ElastiCache involves configuring your Virtual Private Cloud (VPC), security groups, and network access controls to control access to your ElastiCache clusters.

    This helps ensure that the data is safe and protected from any threats and or misconfigurations within the network. This helps to keep a potential hacker getting into the system and compromising the data.
  "
  desc  'check', "
    1. Create or Select a VPC
    - Sign in to the AWS Management Console and open the Amazon VPC console at https://console.aws.amazon.com/vpc/.
    - Create a new VPC or select an existing VPC where you want to deploy your ElastiCache cluster.

    2. Create Subnets
    - In the VPC console, navigate to `Subnets` in the left-side menu.
    - Create or select the desired subnets within your VPC where you want to deploy your ElastiCache cluster.

    3. Configure Security Groups
    - In the VPC console, navigate to `Security Groups` in the left-side menu.
    - Create a new security group.
    Or select an existing one to configure the security settings for your ElastiCache cluster.
    - Define inbound and outbound rules to control the traffic flow to and from your ElastiCache cluster.
    	- Allow inbound traffic from trusted sources (e.g., specific IP ranges or security groups) on the necessary ports used by your ElastiCache cluster.
    	- Define outbound rules based on your requirements, such as allowing outbound traffic to specific destinations or ports.
    - Associate the security group with the ElastiCache cluster when creating or modifying it.
 
    4. Set up Network Access Control Lists (ACLs)
    - In the VPC console, navigate to `Network ACLs` in the left-side menu.
    - Create or select the appropriate network ACL associated with the subnets used by your ElastiCache cluster.
    - Configure inbound and outbound rules in the network ACL to allow or deny traffic to and from your ElastiCache cluster.
    	- Define rules based on your security requirements, allowing only necessary protocols, ports, and IP ranges.
    - Associate the network ACL with the subnets used by your ElastiCache cluster.

    5. Configure Route Tables
    - In the VPC console, navigate to `Route Tables` in the left-side menu.
    - Create or select the route table associated with the subnets used by your ElastiCache cluster.
    - Add or modify routes to ensure traffic to and from your ElastiCache cluster flows correctly.
    	- Ensure that the route table has an appropriate route to the internet gateway or virtual private gateway if external connectivity is required.
    - Associate the route table with the subnets used by your ElastiCache cluster.

    6. Verify Connectivity and Test
    - Launch an Amazon EC2 instance within the same VPC and subnet as your ElastiCache cluster or use an existing one.
    - Connect to the EC2 instance using SSH or other remote access methods.
    - Test the connectivity to your ElastiCache cluster by trying to connect to it using the appropriate client or utility.
    - Verify that the network security settings allow the necessary traffic and deny unauthorized access.
  "
  desc  'fix', "
    1. Confirm the cluster is in a cache subnet group made of private subnets across
       at least two Availability Zones.
    2. Give the cluster its own security group rather than reusing the application's,
       and allow only the cache port from the application security group.
    3. Verify no NACL or route permits inbound traffic from outside the VPC to the
       cache subnets.
    4. Where clients are in another VPC, use peering or Transit Gateway with a scoped
       route rather than making the cluster publicly reachable.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SA-8']
  tag nist_r4:               ['SA-8']
  tag cci:                   ['CCI-000664']
  tag cis_number:            '5.2'
  tag cis_rid:               '5.2'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0502r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('elasticache')
  impact 0.5
  scoped_items = scoped_or_na(aws_elasticache_clusters.ids,
                              in_scope: applicable_partition && applicable_service,
                              reason:   "ELASTICACHE out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')}) or none present in this account")

  scoped_items.each do |id|
    describe aws_elasticache_cluster(cache_cluster_id: id) do
      its('security_group_ids') { should_not be_empty }
    end
  end
end
