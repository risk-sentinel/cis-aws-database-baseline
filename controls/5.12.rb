# encoding: UTF-8

control 'C-5.12' do
  title 'Ensure ElastiCache is deployed across multiple Availability Zones (AZs)'
  desc  "
    Deploying Amazon ElastiCache across multiple Availability Zones means configuring the cache cluster nodes (primary and replicas) to be distributed in different AZs within the same AWS region. This multi-AZ deployment improves fault tolerance and availability by mitigating risks associated with failure or degradation in a single Availability Zone. If the primary node or an AZ becomes unavailable, ElastiCache can automatically fail over to a replica in a different AZ, minimizing downtime and data unavailability.

    Distributing ElastiCache nodes across multiple AZs protects the caching layer from localized infrastructure failures, such as power outages, networking disruptions, or hardware faults in a single AZ.
  "
  desc  'rationale', "
    Deploying Amazon ElastiCache across multiple Availability Zones means configuring the cache cluster nodes (primary and replicas) to be distributed in different AZs within the same AWS region. This multi-AZ deployment improves fault tolerance and availability by mitigating risks associated with failure or degradation in a single Availability Zone. If the primary node or an AZ becomes unavailable, ElastiCache can automatically fail over to a replica in a different AZ, minimizing downtime and data unavailability.

    Distributing ElastiCache nodes across multiple AZs protects the caching layer from localized infrastructure failures, such as power outages, networking disruptions, or hardware faults in a single AZ.
  "
  desc  'check', "
    Audit All Replication Groups for Multi-AZ Status:

    ```
    aws elasticache describe-replication-groups --query \"ReplicationGroups[*].{ID:ReplicationGroupId,MultiAZ:MultiAZ}\"
    ```

    This returns true if Multi-AZ with automatic failover is enabled, otherwise false.
  "
  desc  'fix', "
    1. Prerequisites for Enabling Multi-AZ on ElastiCache
    - VPC with Subnets in Multiple Availability Zones: The VPC associated with your ElastiCache replication group must have at least two subnets in different Availability Zones within the same AWS Region.

    - Cache Subnet Group Configuration: The cache subnet group used by the replication group must include multiple subnets spanning the desired AZs to support node placement.​

    - Replication Group with At Least One Replica: Multi-AZ requires a primary node and at least one read replica that can be deployed in a different AZ to support automatic failover.​

    - Automatic Failover Enabled: Failover between primary and replicas is automatic with Multi-AZ, so automatic failover must be enabled on the replication group (can be set at creation or modified later).

    2. Modify the Replication Group to Enable Multi-AZ:

    ```
    aws elasticache modify-replication-group \\
      --replication-group-id \\
      --multi-az-enabled \\
      --apply-immediately
    ```

    - This command enables Multi-AZ with automatic failover for the specified replication group.

    - The --apply-immediately flag ensures the change happens without waiting for the next maintenance window. Use with caution in production.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '5.12'
  tag cis_rid:               '5.12'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0512r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('elasticache')
  impact 0.5
  scoped_items = scoped_or_na(aws_elasticache_replication_groups.ids,
                              in_scope: applicable_partition && applicable_service,
                              reason:   "ELASTICACHE out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')}) or none present in this account")

  scoped_items.each do |id|
    describe aws_elasticache_replication_group(replication_group_id: id) do
      its('multi_az') { should cmp 'enabled' }
    end
  end
end
