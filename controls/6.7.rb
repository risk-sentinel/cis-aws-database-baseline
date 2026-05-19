# encoding: UTF-8

control 'C-6.7' do
  title 'Ensure MemoryDB has automatic backups enabled'
  desc  "
    Ensure that Amazon MemoryDB clusters that store critical or stateful data have automatic backups enabled with a non-zero retention period. This setting configures MemoryDB to take snapshots of database and retain them for a defined number of days, allowing restoration of data in case of corruption, accidental deletion, or infrastructure failure.

    Automatic backups provide a simple and reliable way to recover MemoryDB data without relying solely on application-level safeguards. In the event of node failure, misconfiguration, or data corruption, a recent backup snapshot can be used to create a new database, significantly reducing recovery time and impact on dependent applications.
  "
  desc  'rationale', "
    Ensure that Amazon MemoryDB clusters that store critical or stateful data have automatic backups enabled with a non-zero retention period. This setting configures MemoryDB to take snapshots of database and retain them for a defined number of days, allowing restoration of data in case of corruption, accidental deletion, or infrastructure failure.

    Automatic backups provide a simple and reliable way to recover MemoryDB data without relying solely on application-level safeguards. In the event of node failure, misconfiguration, or data corruption, a recent backup snapshot can be used to create a new database, significantly reducing recovery time and impact on dependent applications.
  "
  desc  'check', "
    List snapshot settings for all memorydb clusters

    ```
    aws memorydb describe-clusters \\
      --query \"Clusters[*].{Name:Name,SnapshotRetentionLimit:SnapshotRetentionLimit}\"
    ```
    - SnapshotRetentionLimit > 0 ⇒ automatic snapshots enabled.
    - SnapshotRetentionLimit = 0 or missing/null ⇒ automatic snapshots disabled.
  "
  desc  'fix', "
    Enable automatic snapshots on a specific cluster

    ```
    aws memorydb update-cluster \\
      --cluster-name \\
      --snapshot-retention-limit 7 \\
      --snapshot-window \"03:00-04:00\"
    ```
    - --snapshot-retention-limit 7 configures a 7‑day retention; use a value aligned with your policy (for example 7, 14, or 30 days).​
    - --snapshot-window \"03:00-04:00\" (optional) sets the daily snapshot window in UTC. Choose an off‑peak period to minimize performance impact.​
    - MemoryDB applies these changes immediately for the cluster configuration.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '6.7'
  tag cis_rid:               '6.7'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0607r1_rule'
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
      its('clusters_without_backups') { should be_empty }
    end
  end
end
