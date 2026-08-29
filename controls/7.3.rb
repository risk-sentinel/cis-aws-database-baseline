# encoding: UTF-8

control 'C-7.3' do
  title 'Ensure Encryption at Rest is Enabled'
  desc  "
    This helps ensure that the data is kept secure and protected when at rest. The user must choose from two key options which then determine when the data is encrypted at rest.
  "
  desc  'rationale', "
    This helps ensure that the data is kept secure and protected when at rest. The user must choose from two key options which then determine when the data is encrypted at rest.
  "
  desc  'check', "
    1. Sign into the AWS Management Console
    - Sign into the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon DocumentDB Console
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/docdb/.

    3. Select the DocumentDB Cluster
    - Choose the Amazon DocumentDB cluster for which you want to enable encryption at rest. 
    - Click on the cluster name to access its details page.
    - In the cluster details page, navigate to the \"Configuration\" section.

    4. Enable Encryption at Rest
    - Under the `Storage` section.
    - Click on the \"Edit\" button or \"Modify\" option to configure the encryption settings.
    - Choose the option to enable encryption at rest for the cluster.

    5. Choose the Encryption Key
    - Select the AWS Key Management Service (KMS) key that you want to use for encrypting your DocumentDB data.
    - You can choose an existing KMS key or create a new one.
    - Ensure that the KMS key you select has appropriate permissions for DocumentDB to use it.

    6. Save the Configuration
    - Click the `Save` button to apply the encryption at rest configuration.
    - DocumentDB will start the process of encrypting the existing data and all new data written to the cluster.

    7. Verify Encryption Status
    - Monitor the cluster status to ensure that the encryption process is completed successfully.
    - Once the encryption is enabled, the cluster status will reflect the updated encryption status.

    8. Test Connectivity
    - Validate that you can still connect to the DocumentDB cluster after enabling encryption at rest.
    - Ensure that your applications and authorized users can access the encrypted data.

    9. Monitor and Manage Encryption
    - Regularly monitor the encryption status of your DocumentDB cluster.
    - Ensure that the encryption remains enabled and that no unauthorized modifications are made.
  "
  desc  'fix', "
    Encryption at rest is set at cluster creation and cannot be enabled in place.

    1. Snapshot the cluster, copy the snapshot with a KMS key, and restore:

        ```
        aws docdb copy-db-cluster-snapshot --source-db-cluster-snapshot-identifier <snapshot-id> --target-db-cluster-snapshot-identifier <snapshot-id>-enc --kms-key-id <kms-key-arn>
        aws docdb restore-db-cluster-from-snapshot --db-cluster-identifier <new-cluster-id> --snapshot-identifier <snapshot-id>-enc --engine docdb
        ```

    2. Use a customer-managed key so key use is recorded and revocable.
    3. After cutover, delete the unencrypted cluster and its snapshots - they still
       hold the data.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-28', 'AC-8 a']
  tag cci:                   ['CCI-001199', 'CCI-000051']
  tag cis_number:            '7.3'
  tag cis_rid:               '7.3'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0703r1_rule'
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
    its('clusters_without_storage_encrypted') { should be_empty }
  end
end
