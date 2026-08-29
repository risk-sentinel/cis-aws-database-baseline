# encoding: UTF-8

control 'C-10.10' do
  title 'Ensure Database has automated Backups enabled'
  desc  "
    Ensure that Amazon Timestream tables have automated backups enabled through AWS Backup with a defined backup schedule and retention policy. AWS Backup provides scheduled, automated backup functionality for Timestream tables, creating regular point-in-time snapshots that are retained according to a configurable lifecycle policy.

    Amazon Timestream stores critical time-series data that is often mission-critical for monitoring, analytics, and operational intelligence. Automated backups through AWS Backup ensure that Timestream tables are continuously protected without requiring manual intervention, and can be rapidly restored in the event of accidental deletion, data corruption, misconfiguration, or application errors.
  "
  desc  'rationale', "
    Ensure that Amazon Timestream tables have automated backups enabled through AWS Backup with a defined backup schedule and retention policy. AWS Backup provides scheduled, automated backup functionality for Timestream tables, creating regular point-in-time snapshots that are retained according to a configurable lifecycle policy.

    Amazon Timestream stores critical time-series data that is often mission-critical for monitoring, analytics, and operational intelligence. Automated backups through AWS Backup ensure that Timestream tables are continuously protected without requiring manual intervention, and can be rapidly restored in the event of accidental deletion, data corruption, misconfiguration, or application errors.
  "
  desc  'check', "
    Important Note: Amazon Timestream does not have a native automated backup feature built into the service. Instead, backups are managed through AWS Backup, which provides scheduled, on-demand, and lifecycle-managed backup functionality for Timestream tables.

    Check if automated backups are enabled via AWS Backup Service:

    1. Check if Timestream Database is Assigned to a Backup Plan

    - List backup plans:
    ```
    aws backup list-backup-plans --query \"BackupPlansList[].BackupPlanName\" --output table
    ```

    - For each backup plan, list all backup selections (resource assignments):
    ```
    aws backup list-backup-selections --backup-plan-id --query \"BackupSelections[].SelectionId\" --output text
    ```

    - For each selection, list assigned resources and search for your database:
    ```
    aws backup get-backup-selection --backup-plan-id --selection-id --query \"BackupSelection.Resources\" --output text
    ```
    - If your table ARN appears in any selection, it is protected by the backup plan.

    2. Verify Backup Plan Configuration

    ```
    aws backup get-backup-plan --backup-plan-id ```

    Look for the \"Lifecycle\" fields in each backup rule:
    - \"DeleteAfterDays\" is the retention period.
    - \"ScheduleExpression\" sets the backup schedule (cron format).
    - \"BackupVaultName\" is the name of the vault (where backups are stored).
  "
  desc  'fix', "
    1. Create Backup Plan for on-demand snapshots:

    ```
    aws backup create-backup-plan --backup-plan '{
      \"BackupPlanName\": \" \",
      \"Rules\": [
        {
          \"RuleName\": \"Scheduled-OnDemand-Snapshots\",
          \"TargetBackupVaultName\": \"Default\",
          \"ScheduleExpression\": \"cron(0 3 ? * SUN *)\",
          \"StartWindowMinutes\": 120,
          \"CompletionWindowMinutes\": 360,
          \"Lifecycle\": { \"DeleteAfterDays\": 90 },
          \"RecoveryPointTags\": { \"BackupType\": \"OnDemand\" }
        }
      ]
    }'
    ```
    - Replace \"BackupPlanName\" with your backup plan name
    - Replace \"Default\" with your actual backup vault name if different
    - Update the \"ScheduleExpression\", \"StartWindowMinutes\" based on your unique backup schedule. 
    - Replace \"35\" with your retention time for PITR if shorter
    - Replace \"90\" with your retention time for Snapshots if different

    This command outputs the BackupPlanId necessary for the next step.

    2. Assign Timestream Database to the Backup Plan

    Replace with the ID from Step 1 and with your Timestream table ARN.

    aws backup create-backup-selection \\
      --backup-plan-id \\
      --backup-selection '{
        \"SelectionName\": \"timestream-tables\",
        \"IamRoleArn\": \"arn:aws:iam:: :role/AWSBackupServiceRolePolicyForBackup\",
        \"Resources\": [\" \"]
      }'
    - Make sure the IAM role has the necessary AWS Backup permissions.
    - These commands create a centralized backup plan with scheduled snapshot backups, then assign your Timestream database as a resource for backup.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '10.10'
  tag cis_rid:               '10.10'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-1010r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('timestream')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("TIMESTREAM out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  inv = aws_timestream_compliance(regions: input('scan_regions'))
  if inv.connection_error
    describe 'Amazon Timestream inventory' do
      skip "Requires manual review and attestation provided for this control (#{inv.connection_error})"
    end
  else
    describe inv do
      its('databases_without_magnetic_storage') { should be_empty }
    end
  end
end
