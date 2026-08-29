# encoding: UTF-8

control 'C-10.2' do
  title 'Ensure Data at Rest is Encrypted'
  desc  "
    Enable encryption at rest for Amazon Timestream to protect your data while it is stored. Utilize AWS Key Management Service (KMS) to manage and control the encryption keys used for data encryption. Configure Timestream to encrypt your data using AWS-managed keys or customer-managed keys.

    This helps ensure that the data is kept secure and protected when at rest. The user must choose from two key options which then determine when the data is encrypted at rest.
  "
  desc  'rationale', "
    Enable encryption at rest for Amazon Timestream to protect your data while it is stored. Utilize AWS Key Management Service (KMS) to manage and control the encryption keys used for data encryption. Configure Timestream to encrypt your data using AWS-managed keys or customer-managed keys.

    This helps ensure that the data is kept secure and protected when at rest. The user must choose from two key options which then determine when the data is encrypted at rest.
  "
  desc  'check', "
    1. Understand Encryption at Rest in Timestream
    Familiarize yourself with the concept of encryption at rest and its importance in securing your data in Timestream.
    Understand that encryption at rest ensures that your data remains protected even if the underlying storage media is compromised.

    2. Create an AWS Key Management Service (KMS) Key
    Open the AWS Management Console and navigate to the AWS Key Management Service (KMS) service.
    Create a new KMS customer master key (CMK) or use an existing one to manage the encryption keys for Timestream.
    Follow the AWS documentation and best practices for creating and managing KMS keys.

    3. Enable Encryption at Rest in Timestream
    Open the Amazon Timestream console.
    Select the Timestream database or table you want to enable encryption at rest.
    Click on the \"Encryption\" tab or section.
    Choose the option to enable encryption at rest.
    Select the KMS key that you created earlier to be used for encryption.

    4. Verify Encryption at Rest
    Confirm that encryption at rest is enabled for the selected Timestream database or table.
    Review the encryption settings in the Timestream console to ensure the correct KMS key is associated.

    5. Monitor and Audit Encryption at Rest
    Regularly monitor the encryption at rest status in the Timestream console.
    Leverage AWS CloudTrail and AWS CloudWatch to monitor and track encryption-related activities or events.
    Set up appropriate alerts and notifications to detect any issues or unauthorized changes to the encryption settings.

    6. Test Data Access and Decryption
    Access the Timestream data that is encrypted at rest.
    Verify that you can retrieve and decrypt the data using the appropriate access controls and KMS key permissions.
    Perform thorough testing to ensure data access and decryption functions as expected.

    7. Review and Update Encryption Configuration
    Regularly review your encryption configuration and settings for Timestream.
    Ensure that the appropriate KMS key is still associated with the Timestream resources.
    Update the encryption settings if necessary, such as rotating encryption keys or modifying key policies.
  "
  desc  'fix', "
    Timestream encrypts at rest by default. Move to a customer-managed key so key
    use is auditable and revocable:

        ```
        aws timestream-write update-database --database-name <database> --kms-key-id <kms-key-arn>
        ```

    1. The key applies to both the memory store and the magnetic store.
    2. Grant the key only to the roles that read and write the database, and alarm on
       `kms:Decrypt` denials, which indicate either misconfiguration or misuse.
    3. Confirm any scheduled query writing to another table uses a key with the same
       protections.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-28', 'AC-8 a']
  tag nist_r4:               ['SC-28']
  tag cci:                   ['CCI-001199', 'CCI-000051']
  tag cis_number:            '10.2'
  tag cis_rid:               '10.2'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-1002r1_rule'
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
      its('databases_without_kms_encryption') { should be_empty }
    end
  end
end
