# encoding: UTF-8

control 'C-8.3' do
  title 'Ensure Data at Rest and in Transit is Encrypted'
  desc  "
    Once a user is logged in to their AWS account and has access to their Amazon Keyspaces they are encouraged to choose from the following two options to encrypt their data. Depending on which key they select for encryption at rest would store the data according to their preference. For encryption in transit the user is also encouraged to choose from two options depending on if the data needs to be encrypted during transit.
  "
  desc  'rationale', "
    Once a user is logged in to their AWS account and has access to their Amazon Keyspaces they are encouraged to choose from the following two options to encrypt their data. Depending on which key they select for encryption at rest would store the data according to their preference. For encryption in transit the user is also encouraged to choose from two options depending on if the data needs to be encrypted during transit.
  "
  desc  'check', "
    1. Sign in to the AWS Management Console
    - Sign in to the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon Keyspaces Console
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/keyspaces/.

    3. Select the Keyspace
    - Choose the Keyspace (database) for which you want to enable encryption at rest and in transit.
    - Click on the Keyspace name to access its details page.

    4. Enable Encryption at Rest
    - In the Keyspace details page, click on the `Configuration` tab.
    - Under the `Encryption` section, locate the \"Encryption at Rest\" option.
    - Click on `Edit`.
    - Select the desired encryption setting:
    	- Default Encryption: Choose this option to use the default AWS-managed key for encryption at rest. Amazon Keyspaces automatically encrypts your data using this default key.
    	- Customer Managed Key (CMK): Choose this option if you want to use your own AWS Key Management Service (KMS) customer-managed key for encryption. Select the appropriate CMK from the dropdown menu.
    - Click \"Save\" to enable encryption at rest for the Keyspace.

    5. Enable Encryption in Transit
    - In the Keyspace details page, click on the `Configuration` tab.
    - Under the `Encryption` section, locate the \"Encryption in Transit\" option.
    - Click on `Edit`.
    - Select the desired encryption setting:
    	- Encryption in Transit Enabled: Choose this option to enable encryption in transit for data transmitted between your client applications and Amazon Keyspaces. Keyspaces support Transport Layer Security (TLS) encryption for secure communication.
    	- Encryption in Transit Disabled: Choose this option if you do not require encryption in transit.
    - Click \"Save\" to enable encryption in transit for the Keyspace.

    6. Verify Encryption Status
    - Wait a few minutes for the changes to propagate and the encryption settings to take effect.
    - Refresh the Keyspace details page to see the updated encryption status.
    - Verify that encryption at rest and in transit are enabled for the Keyspace.
  "
  desc  'fix', "
    1. Tables are encrypted at rest by default with an AWS-owned key. Use a
       customer-managed key where key use must be auditable and revocable:

        ```
        aws keyspaces update-table --keyspace-name <keyspace> --table-name <table> --encryption-specification type=CUSTOMER_MANAGED_KMS_KEY,kms_key_identifier=<kms-key-arn>
        ```

    2. Keyspaces requires TLS for all connections; confirm clients are configured to
       verify the certificate using the Starfield CA bundle rather than disabling
       verification.
    3. Confirm the driver is not configured to fall back to a plaintext port.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-8', 'SC-28', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-001199', 'CCI-000051']
  tag cis_number:            '8.3'
  tag cis_rid:               '8.3'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0803r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('keyspaces')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("KEYSPACES out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  inv = aws_keyspaces_compliance(regions: input('scan_regions'))
  if inv.connection_error
    describe 'Amazon Keyspaces inventory' do
      skip "Requires manual review and attestation provided for this control (#{inv.connection_error})"
    end
  else
    describe inv do
      its('tables_without_encryption') { should be_empty }
    end
  end
end
