# encoding: UTF-8

control 'C-11.7' do
  title 'Ensure to Enable Backup and Recovery'
  desc  "
    Having the data backed up ensures that all the crucial information is stored securely it defends against any human errors and system errors that resulted in data loss. An organization that has a disaster recovery plan is prepared for any disruption that would impact business operations.
  "
  desc  'rationale', "
    Having the data backed up ensures that all the crucial information is stored securely it defends against any human errors and system errors that resulted in data loss. An organization that has a disaster recovery plan is prepared for any disruption that would impact business operations.
  "
  desc  'check', "
    1. Understand QLDB Backup and Recovery Features
    - Familiarize yourself with the built-in backup and recovery capabilities provided by QLDB.
    - Understand the concepts of ledgers, revisions, and journal export for backup and restore operations.

    2. Determine Backup and Recovery Requirements
    - Assess your organization's backup and recovery requirements for QLDB.
    - Define the recovery point objective (RPO) and recovery time objective (RTO) that align with your business needs.
    - Determine the desired backup frequency and retention period for your QLDB data.

    3. Enable Automatic Backups
    - Open the Amazon QLDB console.
    - Select the QLDB ledger for which you want to enable automatic backups.
    - Click on the `Configuration` tab.
    - Under the `Backup` section, enable automatic backups.
    - Specify the desired backup retention period for the automatic backups.

    4. Perform Manual Backups (Optional)
    - If you need additional backups or want to perform on-demand backups, initiate manual backups.
    - Open the Amazon QLDB console.
    - Select the QLDB ledger you want to back up.
    - Click on the `Backups` tab.
    - Choose the `Create Backup` option.
    - Provide a meaningful backup name and initiate the backup process.

    5. Restore QLDB from Backups
    - Open the Amazon QLDB console.
    - Go to the `Backups` tab.
    - Select the backup from which you want to restore the QLDB ledger.
    - Click on the `Restore` option.
    - Specify the desired restoration name and initiate the restoration process.

    6. Regularly Test Restore Process
    - Periodically test the restore process to ensure that backups are working correctly.
    - Select a backup and initiate the restoration to a separate QLDB ledger.
    - Verify that the restored ledger contains the expected data and is accessible.

    7. Implement Data Archiving (Optional)
    - If you require long-term data retention or compliance with specific data retention policies, consider implementing data archiving strategies.
    - Leverage AWS services like Amazon S3 for long-term storage of QLDB journal exports or backups.

    8. Disaster Recovery Planning
    - Develop a comprehensive disaster recovery plan for QLDB to mitigate the impact of catastrophic events.
    - Consider implementing cross-region replication or multi-region deployments to provide geographic redundancy.
    - Test the disaster recovery plan periodically to validate its effectiveness.

    9. Monitor Backup and Recovery Operations
    - Regularly monitor backup and recovery operations using Amazon CloudWatch and AWS CloudTrail.
    - Set up appropriate alarms and notifications to ensure timely identification of any backup or recovery issues.
  "
  desc  'fix', "
    1. Enable deletion protection so the ledger cannot be removed by an accidental
       call:

        ```
        aws qldb update-ledger --name <ledger-name> --deletion-protection
        ```

    2. Export the journal to S3 on a schedule, into a bucket with versioning, default
       encryption and a lifecycle or Object Lock policy matching your retention
       obligation. QLDB has no snapshot or point-in-time restore - the journal export
       is the backup.
    3. Verify an export can be read back and its digest verified. An export that has
       never been validated is not a recovery capability.
    4. Where the ledger is being migrated off QLDB, the export is also the migration
       artefact - test it early.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '11.7'
  tag cis_rid:               '11.7'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-1107r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('redshift')
  impact 0.5
  scoped_items = scoped_or_na(aws_redshift_clusters.cluster_identifiers,
                              in_scope: applicable_partition && applicable_service,
                              reason:   "REDSHIFT out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')}) or none present in this account")

  scoped_items.each do |id|
    describe aws_redshift_cluster(cluster_identifier: id) do
      its('automated_snapshot_retention_period') { should be > 0 }
    end
  end
end
