# encoding: UTF-8

control 'C-4.9' do
  title 'Ensure Database has Backup enabled'
  desc  "
    Ensure your DynamoDB tables have backups enabled to protect against accidental data loss or corruption. This can be achieved in two ways: by enabling Point-in-Time Recovery (PITR), which provides continuous backups for up to 35 days, and by configuring on-demand backups that can be automated using the AWS Backup service.

    Backups are essential for restoring data after accidental deletions, application errors or malicious events. Enabling both continuous and scheduled backups maximizes data resilience while meeting recovery point objectives (RPO) and compliance mandates.
  "
  desc  'rationale', "
    Ensure your DynamoDB tables have backups enabled to protect against accidental data loss or corruption. This can be achieved in two ways: by enabling Point-in-Time Recovery (PITR), which provides continuous backups for up to 35 days, and by configuring on-demand backups that can be automated using the AWS Backup service.

    Backups are essential for restoring data after accidental deletions, application errors or malicious events. Enabling both continuous and scheduled backups maximizes data resilience while meeting recovery point objectives (RPO) and compliance mandates.
  "
  desc  'check', "
    1. Check if Point-in-Time Recovery (PITR) is enabled

    Use the following steps on the AWS console to verify if PITR is enabled for your DynamoDB table and also conform the number of days its retained for:

    1.1 Log in to the AWS Management Console.

    1.2 Navigate to DynamoDB in the AWS Services menu.
    - Select \"Tables\" from the left sidebar.

    1.3 Click on the specific table name that you want to audit.

    1.4 Go to the \"Backups\" tab in the table's navigation bar.

    1.5 Under the \"Point-in-time recovery (PITR)\" section:

    - Verify that \"Status\" is \"On\", which means PITR is enabled.

    - Check the \"Backup recovery period\" value, this displays the configured retention period in days. 

    - Optionally, review the Earliest restore point and Latest restore point timestamps to confirm the exact window for recovery.

    2. Check if automated backups are enabled via AWS Backup Service

    AWS Backup allows scheduled, automated backups of DynamoDB tables (if integrated). To confirm backup plan settings, list backup plans and recovery points:

    2.1 Check if Table is Assigned to a Backup Plan

    - List backup plans:
    ```
    aws backup list-backup-plans --query \"BackupPlansList[].BackupPlanName\" --output table
    ```

    - For each backup plan, list all backup selections (resource assignments):
    ```
    aws backup list-backup-selections --backup-plan-id --query \"BackupSelections[].SelectionId\" --output text
    ```

    - For each selection, list assigned resources and search for your table:

    ```
    aws backup get-backup-selection --backup-plan-id --selection-id --query \"BackupSelection.Resources\" --output text
    ```

    - If your table ARN appears in any selection, it is protected by the backup plan.

    2.2 Verify Backup Plan Configuration

    ```
    aws backup get-backup-plan --backup-plan-id ```
    Look for the \"Lifecycle\" fields in each backup rule:
    - \"DeleteAfterDays\" is the retention period.
    - \"ScheduleExpression\" sets the backup schedule (cron format).
    - \"BackupVaultName\" is the name of the vault (where backups are stored).

    Summary:
    1. Confirm PITR is enabled for the table and note it's retention period (up to 35 days).
    2. Confirm if AWS Backup plans exist and are actively creating recovery points for your DynamoDB tables.
  "
  desc  'fix', "
    1. Create Backup Plan with 2 Rules (Continuous and Scheduled Snapshots)
    ```
    aws backup create-backup-plan --backup-plan '{
      \"BackupPlanName\": \" \",
      \"Rules\": [
        {
          \"RuleName\": \"Continuous-PITR\",
          \"TargetBackupVaultName\": \"Default\",
          \"ScheduleExpression\": \"cron(0 * * * ? *)\",
          \"StartWindowMinutes\": 60,
          \"CompletionWindowMinutes\": 180,
          \"Lifecycle\": { \"DeleteAfterDays\": 35 },
          \"RecoveryPointTags\": { \"BackupType\": \"Continuous\" },
          \"EnableContinuousBackup\": true
        },
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
    - Update the \"ScheduleExpression\", \"StartWindowMinutes\" based on your unique backup schedule. Note, this schedule is ignored for PITR as that is continuous backup. 
    - Replace \"35\" with your retention time for PITR if shorter
    - Replace \"90\" with your retention time for Snapshots if different

    This command outputs the BackupPlanId necessary for the next step.

    2. Assign DynamoDB Table to the Backup Plan

    Replace with the ID from Step 1 and with your DynamoDB table ARN. 

    ```
    aws backup create-backup-selection \\
      --backup-plan-id \\
      --backup-selection '{
        \"SelectionName\": \"DynamoDBTableSelection\",
        \"IamRoleArn\": \"arn:aws:iam:: :role/AWSBackupServiceRolePolicyForBackup\",
        \"Resources\": [\" \"]
      }'
    ```
    - Make sure the IAM role has the necessary AWS Backup permissions.

    These commands create a centralized backup plan with continuous and scheduled snapshot backups, then assign your DynamoDB table as a resource for backup.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '4.9'
  tag cis_rid:               '4.9'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0409r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('dynamodb')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("DYNAMODB out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe aws_dynamodb_compliance(regions: input('scan_regions')) do
    its('tables_without_pitr') { should be_empty }
  end
end
