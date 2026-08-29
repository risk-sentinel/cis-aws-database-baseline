# encoding: UTF-8

control 'C-5.11' do
  title 'Ensure ElastiCache has Cluster Mode Enabled'
  desc  "
    Cluster Mode Enabled for ElastiCache distributes data across multiple shards, enabling horizontal scaling, higher availability, and isolating potential failures or resource exhaustion to a subset of the data set, rather than the entire cluster.

    Enabling Cluster Mode reduces the risk of service outage from node failures, hardware limits, or scaling bottlenecks. Data partitioning across shards allows zero-downtime horizontal scaling, automated failover, and better resource utilization in production workloads, especially under high load or large data sets.
  "
  desc  'rationale', "
    Cluster Mode Enabled for ElastiCache distributes data across multiple shards, enabling horizontal scaling, higher availability, and isolating potential failures or resource exhaustion to a subset of the data set, rather than the entire cluster.

    Enabling Cluster Mode reduces the risk of service outage from node failures, hardware limits, or scaling bottlenecks. Data partitioning across shards allows zero-downtime horizontal scaling, automated failover, and better resource utilization in production workloads, especially under high load or large data sets.
  "
  desc  'check', "
    List Cluster Mode Status for All Replication Groups

    ```
    aws elasticache describe-replication-groups \\
      --query \"ReplicationGroups[*].{ReplicationGroupId:ReplicationGroupId, ClusterModeEnabled:ClusterEnabled}\"
    ```

    - This will output a concise list showing each cluster's ID and whether Cluster Mode is enabled (true) or not (false).

    - Review and flag any replication group entries where \"ClusterModeEnabled\": false.
  "
  desc  'fix', "
    Migration from Cluster Mode Disabled (CMD) to Cluster Mode Enabled (CME) is possible via the cluster mode compatible feature provided by AWS. 

    1. Pre-requisites:
    - The cluster may only have keys in database 0 only.
    - Applications must use a Valkey or Redis OSS client that is capable of using Cluster protocol and use a configuration endpoint.
    - Auto-failover must be enabled on the cluster with a minimum of 1 replica.
    - The minimum engine version required for migration is Valkey 7.2 and above, or Redis OSS 7.0 and above.

    2. Modify Cluster Mode to Compatible
    - Change the existing replication group cluster mode from disabled to Compatible:

    ```
    aws elasticache modify-replication-group \\
      --replication-group-id \\
      --cluster-mode compatible \\
      --apply-immediately
    ```

    - In this mode, ElastiCache behaves as a single shard cluster but supports both cluster mode enabled and disabled client connections.

    3. Migrate All Clients to Cluster Mode Enabled

    - Update your application clients to support the cluster protocol using the cluster configuration endpoint.

    - Validate application behavior in this intermediate compatible mode.

    - This allows your client applications to start transitioning to the cluster-aware mode while maintaining backward compatibility.

    4. Complete Cluster Mode Configuration

    - Once all client applications have been migrated and validated, finalize the cluster mode by switching from Compatible to Enabled:

    ```
    aws elasticache modify-replication-group \\
      --replication-group-id \\
      --cluster-mode enabled \\
      --apply-immediately
    ```

    - This enforces cluster mode fully, allowing scaling and other cluster features to be enabled.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '5.11'
  tag cis_rid:               '5.11'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0511r1_rule'
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
      its('cluster_enabled') { should eq true }
    end
  end
end
