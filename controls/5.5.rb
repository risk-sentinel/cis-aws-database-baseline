# encoding: UTF-8

control 'C-5.5' do
  title 'Ensure Virtual Private Cloud (VPC) is Enabled'
  desc  "
    Implementing VPC security best practices for Amazon ElastiCache involves configuring your Virtual Private Cloud (VPC) and associated resources to enhance the security of your ElastiCache clusters.

    This ensures that only authorized users can access their platforms and prevents any mistakes that can lead to a data breach due to the level of security.
  "
  desc  'rationale', "
    Implementing VPC security best practices for Amazon ElastiCache involves configuring your Virtual Private Cloud (VPC) and associated resources to enhance the security of your ElastiCache clusters.

    This ensures that only authorized users can access their platforms and prevents any mistakes that can lead to a data breach due to the level of security.
  "
  desc  'check', "
    1. Create or Select a VPC
    - Sign in to the AWS Management Console and open the Amazon VPC console at https://console.aws.amazon.com/vpc/.
    - Create a new VPC or select an existing VPC to host your ElastiCache clusters.

    2. Configure Subnets
    - In the VPC console, navigate to `Subnets` in the left-side menu.
    - Create or select the subnets within your VPC where you want to deploy your ElastiCache clusters.
    - Ensure you have private subnets for your ElastiCache clusters to avoid exposing them to the public internet.

    3. Define Security Groups
    - In the VPC console, navigate to `Security Groups` in the left-side menu.
    - Create a new security group or select an existing one for your ElastiCache clusters.
    - Configure inbound and outbound rules in the security group to control traffic access.
    	- Allow inbound access only from trusted sources or specific IP ranges required for your applications.
    	- Restrict outbound access to necessary destinations and protocols.
    - Associate the security group with your ElastiCache clusters.

    4. Configure Network Access Control Lists (ACLs)
    - In the VPC console, navigate to `Network ACLs` in the left-side menu.
    - Create or select the network ACLs associated with the subnets used by your ElastiCache clusters.
    - Configure inbound and outbound rules in the network ACLs to control traffic access.
    	- Define rules based on your security requirements, allowing only necessary protocols, ports, and IP ranges.
    	- Deny unnecessary or unwanted traffic.
    - Associate the network ACLs with the subnets used by your ElastiCache clusters.

    5. Configure Routing
    - In the VPC console, navigate to `Route Tables` in the left-side menu.
    - Create or select the route table associated with the subnets used by your ElastiCache clusters.
    - Add or modify routes to ensure traffic flows correctly to and from your ElastiCache clusters.
    - Ensure that the route table has appropriate routes to the internet gateway or virtual private gateway if external connectivity is required.
    - Associate the route table with the subnets used by your ElastiCache clusters.

    6. Review and Update Network Security Settings
    - Regularly review and update your VPC security configurations, including security groups, network ACLs, and routing, to align with your security requirements.
    - Remove any unnecessary or excessive permissions from security groups and tighten inbound and outbound access as needed.
    - Stay informed about AWS security best practices and recommendations to enhance your network security.
  "
  desc  'fix', "
    The individual is required to create a subnet and configure their inbound and outbound access. Individuals are supposed to configure their ACL and routing ensuring the traffic is flowing smoothly without any interference. This control is important because it only allows authorized user to access their resources as they prefer.
  "
  tag severity:              'medium'
  tag nist:                  ['SA-8']
  tag cci:                   ['CCI-000664']
  tag cis_number:            '5.5'
  tag cis_rid:               '5.5'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0505r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('elasticache')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("ELASTICACHE out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  aws_elasticache_clusters.ids.each do |id|
    describe aws_elasticache_cluster(cache_cluster_id: id) do
      its('cache_subnet_group_name') { should match(/\S/) }
    end
  end
end
