# encoding: UTF-8

control 'C-9.9' do
  title 'Ensure Neptune Database has automatic backups enabled'
  desc  "
    Ensure that Amazon Neptune DB clusters have automated backups enabled with a non-zero backup retention period (for example, 7 to 35 days). Neptune automatically creates continuous, incremental backups of cluster data and retains them for the configured retention period, allowing point-in-time recovery to any second within the backup window.

    Enabling automated backups with a sufficient retention period ensures that Neptune cluster data can be quickly recovered to any point within the retention window, protecting against accidental deletions, data corruption, application errors, and infrastructure failures. Neptune backups are continuous and incremental, providing robust disaster recovery and business continuity capabilities with minimal storage overhead.
  "
  desc  'rationale', "
    Ensure that Amazon Neptune DB clusters have automated backups enabled with a non-zero backup retention period (for example, 7 to 35 days). Neptune automatically creates continuous, incremental backups of cluster data and retains them for the configured retention period, allowing point-in-time recovery to any second within the backup window.

    Enabling automated backups with a sufficient retention period ensures that Neptune cluster data can be quickly recovered to any point within the retention window, protecting against accidental deletions, data corruption, application errors, and infrastructure failures. Neptune backups are continuous and incremental, providing robust disaster recovery and business continuity capabilities with minimal storage overhead.
  "
  desc  'check', "
    List backup retention status for all Neptune DB clusters:

    ```
    aws neptune describe-db-clusters \\
      --query \"DBClusters[*].{DBClusterIdentifier:DBClusterIdentifier,Engine:Engine,BackupRetentionPeriod:BackupRetentionPeriod}\"
    ```

    - BackupRetentionPeriod > 0 ⇒ Automated backups are enabled (compliant).
    - BackupRetentionPeriod = 0 or missing/null ⇒ Automated backups are not enabled (non-compliant).
  "
  desc  'fix', "
    Enable automated backups on a specific Neptune cluster:

    ```
    aws neptune modify-db-cluster \\
      --db-cluster-identifier \\
      --backup-retention-period 7 \\
      --preferred-backup-window \"03:00-04:00\" \\
      --apply-immediately
    ```
    - --backup-retention-period 7 sets a 7-day retention; use a value between 1 and 35 days aligned with your policy.​
    - --preferred-backup-window \"03:00-04:00\" (optional) sets the daily UTC backup window during off-peak hours to minimize performance impact.​
    - --apply-immediately applies the change without waiting for the next maintenance window.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '9.9'
  tag cis_rid:               '9.9'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0909r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('neptune')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("NEPTUNE out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe aws_rds_cluster_compliance(
    regions:                          input('scan_regions'),
    engines:                          ['neptune'],
    backup_retention_minimum_days:    input('rds_backup_retention_minimum_days'),
  ) do
    its('clusters_without_backup_retention') { should be_empty }
  end
end
