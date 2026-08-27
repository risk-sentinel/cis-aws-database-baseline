# encoding: UTF-8

control 'C-3.5' do
  title 'Enable Encryption at Rest'
  desc  "
    This helps ensure that the data is kept secure and protected when at rest. The user must choose from two key options which then determine when the data is encrypted at rest.
  "
  desc  'rationale', "
    This helps ensure that the data is kept secure and protected when at rest. The user must choose from two key options which then determine when the data is encrypted at rest.
  "
  desc  'check', "
    1. Sign into the AWS Management Console 
    - Sign into the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon RDS Console 
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/rds/.

    3. Select the RDS Instance 
    - Choose the Amazon RDS instance you want to enable encryption at rest. 
    - Click on the instance name to access its details page.
    - In the instance details page, navigate to the `Configuration` or `Encryption & Security` section.

    4. Enable Encryption at Rest
    - Under the `Encryption` or `Encryption at Rest` section
    - Click on the `Modify` button or the `Enable` option to enable encryption at rest.
    - Choose the desired encryption option, either `AWS managed keys (default)` or `Customer managed keys using AWS Key Management Service (KMS)`.
    - If selecting `AWS managed keys`, you do not need to perform additional configuration steps.
    - If selecting `Customer managed keys` you will need to specify the KMS key you want to use for encryption.
    - Select the appropriate KMS key or create a new KMS key if necessary.
    - Click `Continue` or `Save` to apply the changes.

    5. Monitor the Encryption Status
    - After enabling encryption at rest, monitor the encryption status of your RDS instance.
    - In the RDS console, check the `Encryption` or `Encryption at Rest` section to ensure that encryption is enabled, and the status is `In Progress` or `Enabled`.

    6. Verify Encryption at Rest
    - Validate that data at rest is encrypted by accessing the RDS instance and examining the database files.
    - Confirm that the data is stored in an encrypted format.
  "
  desc  'fix', "
    Encryption at rest is set at creation and cannot be enabled in place, so
    remediation means creating an encrypted copy.

    1. Snapshot the unencrypted instance, copy the snapshot with a KMS key, and
       restore from the encrypted copy:

        ```
        aws rds copy-db-snapshot --source-db-snapshot-identifier <snapshot-id> --target-db-snapshot-identifier <snapshot-id>-enc --kms-key-id <kms-key-arn>
        aws rds restore-db-instance-from-db-snapshot --db-instance-identifier <new-instance-id> --db-snapshot-identifier <snapshot-id>-enc
        ```

    2. Use a customer-managed key so access can be revoked and rotation audited
       independently of RDS.
    3. Cut the application over, then delete the unencrypted instance and its
       snapshots - the old snapshots remain unencrypted and still contain the data.
  "
  tag severity:              'medium'
  tag nist:                  ['SC-28', 'AC-8 a']
  tag cci:                   ['CCI-001199', 'CCI-000051']
  tag cis_number:            '3.5'
  tag cis_rid:               '3.5'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0305r1_rule'
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

  # Same technical bar as CIS 2.2 — redundant coverage by design.
  allowed_engines = Array(input('rds_engines'))

  scoped_items.each do |c|
    next unless allowed_engines.empty? || allowed_engines.include?(c[:engine])

    describe aws_rds_cluster(db_cluster_identifier: c[:db_cluster_identifier]) do
      its('storage_encrypted') { should eq true }
    end
  end
end
