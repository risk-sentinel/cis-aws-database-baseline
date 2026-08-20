# encoding: UTF-8

control 'C-5.13' do
  title 'Ensure ElastiCache has automatic backups enabled'
  desc  "
    Ensure that Amazon ElastiCache clusters that store critical or stateful data have automatic backups enabled with a non-zero retention period. This setting configures ElastiCache to take daily snapshots of caches and retain them for a defined number of days, allowing restoration of data in case of corruption, accidental deletion, or infrastructure failure.

    Automatic backups provide a simple and reliable way to recover ElastiCache data without relying solely on application-level safeguards. In the event of node failure, misconfiguration, or data corruption, a recent backup snapshot can be used to create a new cache or replication group, significantly reducing recovery time and impact on dependent applications.
  "
  desc  'rationale', "
    Ensure that Amazon ElastiCache clusters that store critical or stateful data have automatic backups enabled with a non-zero retention period. This setting configures ElastiCache to take daily snapshots of caches and retain them for a defined number of days, allowing restoration of data in case of corruption, accidental deletion, or infrastructure failure.

    Automatic backups provide a simple and reliable way to recover ElastiCache data without relying solely on application-level safeguards. In the event of node failure, misconfiguration, or data corruption, a recent backup snapshot can be used to create a new cache or replication group, significantly reducing recovery time and impact on dependent applications.
  "
  desc  'check', "
    1. List backup settings for all cache clusters (node-based):

    ```
    aws elasticache describe-cache-clusters \\
      --show-cache-node-info \\
      --query \"CacheClusters[*].{Id:CacheClusterId,Engine:Engine,SnapshotRetentionLimit:SnapshotRetentionLimit}\"
    ```
    - SnapshotRetentionLimit > 0 ⇒ automatic backups enabled.
    - SnapshotRetentionLimit = 0 or null ⇒ automatic backups disabled.

    2. List backup settings for all replication groups (Redis/Valkey):

    ```
    aws elasticache describe-replication-groups \\
      --query \"ReplicationGroups[*].{Id:ReplicationGroupId,Engine:Engine,SnapshotRetentionLimit:SnapshotRetentionLimit}\"
    ```
    - Again, treat SnapshotRetentionLimit = 0 as non-compliant for this control.
  "
  desc  'fix', "
    Enable backups on a replication group (Redis/Valkey):

    ```
    aws elasticache modify-replication-group \\
      --replication-group-id \\
      --snapshot-retention-limit 7 \\
      --snapshotting-cluster-id \\
      --apply-immediately
    ```
    - replication-group-id is your replication group (e.g., my-redis-rg).
    - primary-cache-cluster-id is the cache cluster ID that should be used as the daily snapshot source (often the primary node, like my-redis-rg-001).
    - snapshot-retention-limit 7 sets a 7‑day retention; choose a value (1-35 days) per your policy.​
    - Optionally set or adjust --preferred-maintenance-window or a specific --snapshot-window if supported for your engine/version.​
    - Use --apply-immediately for immediate effect; omit it to apply in the next maintenance window.

    - You can find the cluster IDs with:

    ```
    aws elasticache describe-cache-clusters \\
      --show-cache-node-info \\
      --query \"CacheClusters[*].{Id:CacheClusterId,ReplicationGroupId:ReplicationGroupId}\"
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '5.13'
  tag cis_rid:               '5.13'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0513r1_rule'
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
      its('snapshot_retention_limit') { should be > 0 }
    end
  end
end
