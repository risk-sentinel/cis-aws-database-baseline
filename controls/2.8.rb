# encoding: UTF-8

control 'C-2.8' do
  title 'Ensure Automatic Backups and Retention Policies are configured'
  desc  "
    Backups help protect your data from accidental loss or database failure. With Amazon Aurora, you can turn on automatic backups and specify a retention period. The backups include a daily snapshot of the entire DB instance and transaction logs.

    The individual logs into their account and chooses their database once selected they can modify the backup settings. To have the database being backed up automatically the individual is encouraged to select from 1 to 35 days.  This ensures that the file is being saved automatically and can prevent it from accidental loss. This ensures that the individual can restore their files quickly in the event of a data loss.
  "
  desc  'rationale', "
    Backups help protect your data from accidental loss or database failure. With Amazon Aurora, you can turn on automatic backups and specify a retention period. The backups include a daily snapshot of the entire DB instance and transaction logs.

    The individual logs into their account and chooses their database once selected they can modify the backup settings. To have the database being backed up automatically the individual is encouraged to select from 1 to 35 days.  This ensures that the file is being saved automatically and can prevent it from accidental loss. This ensures that the individual can restore their files quickly in the event of a data loss.
  "
  desc  'check', "
    1. Sign in to AWS Management Console 
    - If you do not already have an AWS account, you will need to create one at https://aws.amazon.com.

    2. Navigate to Amazon RDS Dashboard 
    - Navigate to the RDS service once logged in to the AWS Management Console. 
    - You can find this under the `Database` category.

    3. Choose your Aurora DB instance 
    - In the RDS Dashboard, click on `Databases`.
    - Then click on the name of your Aurora DB instance.

    4. Check or modify the backup settings
    - In the `Details` section, find the `Backup` section. 
    Here, you can see if automatic backups are enabled (the `Backup retention period` is more than 0 days) and when the backup window is.
    	- To modify these settings, click `Modify`. 
    	- In the `Backup` section of the `Modify DB instance` screen, you can change the `Backup retention period` and the `Backup window`. 
    	- The retention period can be between 1 and 35 days. To disable automatic backups, set the retention period to 0 days.

    5. Apply the changes 
    - Scroll to the bottom and choose when to apply the changes. You can apply them immediately or schedule them for the next maintenance window. 
    - Then, click `Continue` and `Modify DB Instance`.
  "
  desc  'fix', "
    This is important because it would allow the user to automatically save their files and instantly have access to their files when needed.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.8'
  tag cis_rid:               '2.8'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0208r1_rule'
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

  allowed_engines = Array(input('rds_engines'))
  retention_min   = input('rds_backup_retention_minimum_days')

  scoped_items.each do |c|
    next unless allowed_engines.empty? || allowed_engines.include?(c[:engine])

    describe aws_rds_cluster(db_cluster_identifier: c[:db_cluster_identifier]) do
      its('backup_retention_period') { should be >= retention_min }
    end
  end
end
