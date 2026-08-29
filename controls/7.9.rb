# encoding: UTF-8

control 'C-7.9' do
  title 'Ensure to Implement Backup and Disaster Recovery'
  desc  "
    Set up automated backups for your DocumentDB instances to ensure data durability and recoverability. Consider implementing a disaster recovery plan that includes data replication across different availability zones or regions.

    Having the data backed up ensures that all the crucial information is stored securely it defends against any human errors and system errors that resulted in data loss. An organization that has a disaster recovery plan is prepared for any disruption that would impact business operations.
  "
  desc  'rationale', "
    Set up automated backups for your DocumentDB instances to ensure data durability and recoverability. Consider implementing a disaster recovery plan that includes data replication across different availability zones or regions.

    Having the data backed up ensures that all the crucial information is stored securely it defends against any human errors and system errors that resulted in data loss. An organization that has a disaster recovery plan is prepared for any disruption that would impact business operations.
  "
  desc  'check', "
    1. Sign into the AWS Management Console
    - Sign into the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon DocumentDB Console
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/docdb/.

    3. Select the DocumentDB Cluster
    - Choose the Amazon DocumentDB cluster for which you want to implement backup and disaster recovery. 
    - Click on the cluster name to access its details page.
    - In the cluster details page, navigate to the \"Backup\" section.

    4. Enable Automated Backups
    - Under the `Automated backups` section.
    - Click on the `Edit` button or `Modify` option to configure automated backup settings.
    - Enable automated backups by choosing the desired backup retention period.
    - Specify the number of days for which automated backups should be retained.
  "
  desc  'fix', "
        ```
        aws docdb modify-db-cluster --db-cluster-identifier <cluster-id> --backup-retention-period 30 --apply-immediately
        ```

    1. Set retention to meet the stated recovery point objective; automated backups
       give point-in-time restore within that window.
    2. Copy snapshots to a second Region or account for anything whose loss would be
       material.
    3. Enable deletion protection so the cluster cannot be removed by an accidental
       call.
    4. Test a restore and record how long it took. Restore time is the number that
       matters during an incident, and it is rarely what people assume.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '7.9'
  tag cis_rid:               '7.9'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0709r1_rule'
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

  describe aws_rds_cluster_compliance(
    regions:                          input('scan_regions'),
    engines:                          ['docdb'],
    backup_retention_minimum_days:    input('rds_backup_retention_minimum_days'),
  ) do
    its('clusters_without_backup_retention') { should be_empty }
  end
end
