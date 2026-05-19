# encoding: UTF-8

control 'C-6.2' do
  title 'Ensure Data at Rest and in Transit is Encrypted'
  desc  "
    TODO: description missing in source XCCDF
  "
  desc  'rationale', "
    TODO: description missing in source XCCDF
  "
  desc  'check', "
    1. Sign in to the AWS Management Console
    - Sign in to the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon MemoryDB Console
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/memorydb/.

    3. Select the Cluster
    - Choose the MemoryDB cluster for which you want to enable encryption at rest and in transit.
    - Click on the cluster name to access its details page.

    4. Enable Encryption at Rest
    - In the cluster details page, navigate to the `Encryption at Rest` section.
    - Click on `Modify` to edit the encryption settings.
    - Select the desired encryption option:
    	- AWS Managed Key (Default): Choose this option to use the default AWS managed key for encryption at rest. Amazon MemoryDB automatically encrypts your data using this key.
    	- Customer Managed Key (CMK): Choose this option if you want to use your own AWS Key Management Service (KMS) customer-managed key for encryption. Select the appropriate CMK from the dropdown menu.
    - Click \"Apply Changes\" to enable encryption at rest for the MemoryDB cluster.

    5. Enable Encryption in Transit
    - In the cluster details page, navigate to the `Encryption in Transit` section.
    - Click on `Modify` to edit the encryption settings.
    - Select the desired encryption option:
    	- Encryption in Transit Enabled: Choose this option to enable encryption in transit for data transmitted between your client applications and MemoryDB. MemoryDB uses SSL/TLS encryption to secure the communication channel.
    	- Encryption in Transit Disabled: Choose this option if you do not require encryption in transit.
    - Click `Apply Changes` to enable encryption in transit for the MemoryDB cluster.

    6. Verify Encryption Status
    - Wait a few minutes for the changes to propagate and the encryption settings to take effect.
    - Refresh the cluster details page to see the updated encryption status.
    - Verify that encryption at rest and in transit are enabled for the MemoryDB cluster.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'SC-28', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-001199', 'CCI-000051']
  tag cis_number:            '6.2'
  tag cis_rid:               '6.2'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0602r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('memorydb')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("MEMORYDB out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  inv = aws_memorydb_compliance(regions: input('scan_regions'))
  if inv.connection_error
    describe 'AWS MemoryDB inventory' do
      skip "Requires manual review and attestation provided for this control (#{inv.connection_error})"
    end
  else
    describe 'MemoryDB encryption at rest' do
      subject { inv.clusters_without_at_rest_encryption }
      it { should be_empty }
    end
    describe 'MemoryDB TLS encryption in transit' do
      subject { inv.clusters_without_tls }
      it { should be_empty }
    end
  end
end
