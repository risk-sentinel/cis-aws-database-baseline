# encoding: UTF-8

control 'C-3.10' do
  title 'Ensure to Enable Backup and Recovery'
  desc  "
    The individual logs into their AWS account and chooses their Amazon relational database that they want to backup. To have the database being backed up automatically the individual is encouraged to enable backup.  This ensures that the file is being saved automatically and can prevent it from accidental loss. This ensures that the individual can restore their files quickly in the event of a data loss.
  "
  desc  'rationale', "
    The individual logs into their AWS account and chooses their Amazon relational database that they want to backup. To have the database being backed up automatically the individual is encouraged to enable backup.  This ensures that the file is being saved automatically and can prevent it from accidental loss. This ensures that the individual can restore their files quickly in the event of a data loss.
  "
  desc  'check', "
    1. Sign into the AWS Management Console 
    - Sign into the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon RDS Console
     - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/rds/.

    3. Select the RDS Instance 
    - Choose the Amazon RDS instance you want to implement backup and recovery. 
    - Click on the instance name to access its details page.
    - In the instance details page, navigate to the `Backup & Restore` or `Backup` section.

    4. Configure Automated Backups
    - Under the `Backup` section.
    - Click the `Modify` or `Edit` option to configure automated backups.
    - Enable automated backups by selecting the desired backup retention period.
    - Specify the preferred backup window during which automated backups can occur.
    - Choose whether to enable Multi-AZ backups for enhanced durability and availability.
    - Click `Continue` or `Save` to apply the changes.

    5. Restore from Backups
    - In the Amazon RDS console, click on `Snapshots` or `Instances` in the left-side menu.
    - Select the snapshot or instance from which you want to perform a restore.
    - Click `Restore snapshot` or `Restore to point in time` to initiate restoration.
    - Configure the parameters for the restored instance, such as instance identifier, instance class, storage type, and VPC settings.
    - Specify the desired option for creating a new DB instance or restoring to an existing DB instance.
    - Configure additional settings, such as enabling Multi-AZ deployment or enabling encryption.
    - Click \"Restore\" or \"Create\" to initiate the restore process.

    6. Test and Validate the Restored Instance
    - After completing the restore process, test the restored RDS instance to ensure it functions as expected.
    - Verify the data, configuration, and connectivity of the restored instance.

    7. Monitor and Manage Backups
    - Regularly monitor the status and health of your automated backups and manual snapshots.
    - Review the backup retention policy and adjust it to align with your business requirements.
    - Manage and delete older backups or snapshots to free up storage and reduce costs.

    8. Perform Point-in-Time Recovery (Optional)
    - In the Amazon RDS console, click on \"Snapshots\" or `Instances` in the left-side menu.
    - Select the instance for which you want to perform point-in-time recovery.
    - Click on `Restore to point in time` to initiate the point-in-time recovery process.
    - Specify the desired timestamp or time range to restore to.
    - Configure the parameters for the restored instance, similar to the restore from the backup process.
    - Click `Restore` or \"Create\" to initiate the point-in-time recovery process.
  "
  desc  'fix', "
        ```
        aws rds modify-db-instance --db-instance-identifier <instance-id> --backup-retention-period 30 --preferred-backup-window <hh24:mi-hh24:mi> --apply-immediately
        ```

    1. A retention period of 0 disables automated backups and point-in-time
       recovery entirely. Set it to meet your stated recovery point objective.
    2. Copy snapshots to a second Region or account for anything whose loss would be
       material, so an account-level event does not take the backups too.
    3. Enable deletion protection, and confirm final snapshots are taken on delete.
    4. Test a restore. An untested backup is an assumption, and restore time is the
       number that matters during an incident.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '3.10'
  tag cis_rid:               '3.10'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0310r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('rds')
  impact 0.5
  scoped_items = scoped_or_na(aws_rds_clusters.entries,
                              in_scope: applicable_partition && applicable_service,
                              reason:   "RDS out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')}) or none present in this account")

  # Same technical bar as CIS 2.8 — redundant coverage by design.
  allowed_engines = Array(input('rds_engines'))
  retention_min   = input('rds_backup_retention_minimum_days')

  scoped_items.each do |c|
    next unless allowed_engines.empty? || allowed_engines.include?(c[:engine])

    describe aws_rds_cluster(db_cluster_identifier: c[:db_cluster_identifier]) do
      its('backup_retention_period') { should be >= retention_min }
    end
  end
end
