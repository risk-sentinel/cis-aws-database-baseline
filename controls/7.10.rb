# encoding: UTF-8

control 'C-7.10' do
  title 'Ensure to Configure Backup Window'
  desc  "
    Set the preferred backup window to a period of low write activity, distinct from
    the maintenance window.

    Both windows are expressed in UTC, so a window that reads as the middle of the
    night locally may fall in the working day for the cluster. A backup window that
    overlaps maintenance, or that is too short for the data volume, produces missed
    backups that surface only when a restore is attempted.
  "
  desc  'rationale', "
    Set the preferred backup window to a period of low write activity, distinct from
    the maintenance window.

    Both windows are expressed in UTC, so a window that reads as the middle of the
    night locally may fall in the working day for the cluster. A backup window that
    overlaps maintenance, or that is too short for the data volume, produces missed
    backups that surface only when a restore is attempted.
  "
  desc  'check', "
    1. Perform Manual Backups (Optional)
    - If desired, you can also create manual backups of your DocumentDB cluster.
    - In the cluster details page, navigate to the `Backup` section.
    - Click on the `Create backup` button.
    - Provide a name for the backup and confirm the action.

    2. Restore from Backups (Optional)
    - If a disaster occurs or you need to restore your DocumentDB cluster to a previous state, you can restore it from the available backups.
    - In the cluster details page, navigate to the `Backup` section.
    - Choose the backup from which you want to restore.
    - Follow the prompts and provide the necessary information to initiate the restore process.

    3. Test Backup and Restore Procedures
    - Periodically test the backup and restore procedures to ensure they work as expected.
    - Perform test restores on non-production environments to validate the integrity and completeness of the backup data.

    4. Regularly Monitor and Validate Backups
    - Regularly monitor the backup status and validate that the backups are completed successfully.
    - Monitor backup storage usage to ensure it is within the desired limits and plan for additional storage as needed.
  "
  desc  'fix', "
        ```
        aws docdb modify-db-cluster --db-cluster-identifier <cluster-id> --preferred-backup-window <hh24:mi-hh24:mi> --apply-immediately
        ```

    1. Set the backup window to a period of low write activity, and confirm it does
       not overlap the maintenance window.
    2. Both windows are in UTC. A window that looks like the middle of the night
       locally may be the middle of the working day for the cluster.
    3. Confirm the window is long enough for the backup to complete as the data
       volume grows.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '7.10'
  tag cis_rid:               '7.10'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0710r1_rule'
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
    its('clusters_without_backup_window') { should be_empty }
  end
end
