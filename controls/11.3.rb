# encoding: UTF-8

control 'C-11.3' do
  title 'Ensure Data at Rest is Encrypted'
  desc  "
    This helps ensure that the data is kept secure and protected when at rest. The user must choose from two key options which then determine when the data is encrypted at rest.
  "
  desc  'rationale', "
    This helps ensure that the data is kept secure and protected when at rest. The user must choose from two key options which then determine when the data is encrypted at rest.
  "
  desc  'check', "
    1. Create an AWS Key Management Service (KMS) Key
    - Sign in to the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.
    - Open the AWS Key Management Service (KMS) console.
    - Create a new KMS key or select an existing one to encrypt your QLDB data at rest.
    - Configure the key policy to grant the appropriate IAM users or role permissions.

    2. Enable Encryption for QLDB
    - Open the Amazon QLDB console.
    - Choose the QLDB ledger for which you want to enable encryption at rest.
    - Click on the `Configuration` tab.
    - Under the `Encryption` section.
    - Click on the `Edit` button or `Modify` option.
    - Enable encryption for the ledger.
    - Select the KMS key you created or chose in the first step for encrypting the QLDB data.
    - Save the changes to enable encryption at rest for the QLDB ledger.

    3. Verify Encryption Status
    - Once the encryption at rest is enabled, the QLDB console will indicate the encryption status as `Enabled` for the selected ledger.
    - Ensure that the KMS key specified for encryption is the correct key you intended to use.

    4. Testing and Verification
    - Perform read and write operations on your QLDB ledger to validate that the data is encrypted at rest.
    - Verify that you can access and query the encrypted data using appropriate authentication and authorization methods.

    5. Key Management and Rotation
    - Follow AWS best practices for key management, including securely storing and managing the KMS key used for QLDB encryption.
    - Implement a key rotation policy, following AWS recommendations and compliance requirements if required.

    6. Backup and Disaster Recovery
    - Ensure you have appropriate backup and disaster recovery mechanisms for your QLDB data.
    - Consider backing up the KMS key used for encryption to prevent data loss in case of a key compromise or accidental deletion.
  "
  desc  'fix', "
    QLDB encrypts at rest by default. Move to a customer-managed key so key use is
    recorded and revocable:

        ```
        aws qldb update-ledger --name <ledger-name> --kms-key <kms-key-arn>
        ```

    1. Grant the key only to the roles that use the ledger.
    2. Confirm any journal export to S3 lands in a bucket with its own default
       encryption - the export leaves the ledger's protection behind.
  "
  tag severity:              'medium'
  tag nist:                  ['SC-28', 'AC-8 a']
  tag cci:                   ['CCI-001199', 'CCI-000051']
  tag cis_number:            '11.3'
  tag cis_rid:               '11.3'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-1103r1_rule'
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
      its('encrypted') { should eq true }
    end
  end
end
