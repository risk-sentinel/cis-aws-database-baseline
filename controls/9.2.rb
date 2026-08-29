# encoding: UTF-8

control 'C-9.2' do
  title 'Ensure Data at Rest is Encrypted'
  desc  "
    This helps ensure that the data is kept secure and protected when at rest. The user must choose from two key options which then determine when the data is encrypted at rest.
  "
  desc  'rationale', "
    This helps ensure that the data is kept secure and protected when at rest. The user must choose from two key options which then determine when the data is encrypted at rest.
  "
  desc  'check', "
    1. Sign into the AWS Management Console 
    - Sign into the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon Neptune Console 
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/neptune/.

    3. Select the Neptune Cluster 
    - Choose the Amazon Neptune cluster for which you want to enable encryption at rest. 
    - Click on the cluster name to access its details page.

    4. Enable Encryption at Rest
    - In the cluster details page, navigate to the `Configuration` or `Encryption at Rest` section.
    - Under `Encryption at Rest`, click on `Modify`.
    - In the `Encryption at Rest` dialog box, select the encryption option you prefer:
    	- AWS managed key (default): Choose this option to use the default AWS managed key for encryption.
    	- Customer-managed key (CMK): Choose this option if you want to use your own AWS Key Management Service (KMS) customer-managed key for encryption. Select the appropriate CMK from the dropdown menu.
    - Click `Apply Changes` to enable encryption at rest for the Neptune cluster.

    5. Verify Encryption Status
    - Wait a few minutes for the changes and configuration to take effect. 
    - Refresh the cluster details page to see the updated encryption status.
    - Verify that encryption at rest is enabled for the Neptune cluster.
  "
  desc  'fix', "
    Encryption at rest is set at creation and cannot be enabled in place.

        ```
        aws neptune copy-db-cluster-snapshot --source-db-cluster-snapshot-identifier <snapshot-id> --target-db-cluster-snapshot-identifier <snapshot-id>-enc --kms-key-id <kms-key-arn>
        aws neptune restore-db-cluster-from-snapshot --db-cluster-identifier <new-cluster-id> --snapshot-identifier <snapshot-id>-enc --engine neptune
        ```

    1. Use a customer-managed KMS key so decrypt is recorded and access revocable.
    2. Delete the unencrypted cluster and its snapshots after cutover.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-28', 'AC-8 a']
  tag ksi:                   ['KSI-SVC-SIN']
  tag nist_r4:               ['SC-28']
  tag cci:                   ['CCI-001199', 'CCI-000051']
  tag cis_number:            '9.2'
  tag cis_rid:               '9.2'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0902r1_rule'
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

  describe aws_rds_cluster_compliance(regions: input('scan_regions'), engines: ['neptune']) do
    its('clusters_without_storage_encrypted') { should be_empty }
  end
end
