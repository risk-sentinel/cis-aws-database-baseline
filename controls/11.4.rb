# encoding: UTF-8

control 'C-11.4' do
  title 'Ensure Data in Transit is Encrypted'
  desc  "
    Use Transport Layer Security (TLS) to encrypt communications between clients and your QLDB instance. QLDB provides TLS support by default, allowing secure communication over the network. Configure your client applications to use TLS when connecting to QLDB.

    Amazon Quantum Ledger Database (QLDB), uses TLS to encrypt data during transit. To secure your data in transit the individual should identify their client application and what is supported by TLS in order to configure it correctly.
  "
  desc  'rationale', "
    Use Transport Layer Security (TLS) to encrypt communications between clients and your QLDB instance. QLDB provides TLS support by default, allowing secure communication over the network. Configure your client applications to use TLS when connecting to QLDB.

    Amazon Quantum Ledger Database (QLDB), uses TLS to encrypt data during transit. To secure your data in transit the individual should identify their client application and what is supported by TLS in order to configure it correctly.
  "
  desc  'check', "
    1. Understand TLS Encryption for QLDB
    - Learn about Transport Layer Security (TLS) and its role in securing data during transit.
    - Understand how TLS works to establish secure communication channels between clients and QLDB.

    2. Configure Clients for TLS Encryption
    - Ensure that your client applications support TLS encryption for communication with QLDB.
    - Use the appropriate AWS SDK or QLDB driver that provides TLS encryption support.
    - Update your application code or configurations to enable TLS encryption.

    3. Obtain the QLDB Endpoint
    - Sign in to the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.
    - Open the Amazon QLDB console.
    - Locate the QLDB ledger for which you want to enable encryption in transit.
    - Note down the QLDB endpoint for your ledger.

    4. Establish TLS Connection
    - Use the QLDB endpoint obtained earlier to establish a TLS connection between your client application and QLDB.
    - Configure your client application to connect to QLDB using the secure HTTPS protocol.
    - Provide the necessary authentication credentials or tokens required to establish the connection.

    5. Verify TLS Encryption
    - Once the TLS connection is established, verify that the connection is secured using TLS by checking for a valid TLS certificate.
    - Ensure that your client application can communicate securely with QLDB without any errors or warnings related to encryption.

    6. Regularly Update Client Applications
    - Stay updated with the latest versions of the AWS SDKs or QLDB drivers used by your client applications.
    - Regularly update your client applications to leverage the latest TLS encryption features and security enhancements.

    7. Monitor and Review TLS Connections
    - Utilize AWS CloudTrail and Amazon CloudWatch to monitor and log TLS-related events and errors.
    - Review the logs and alerts to identify potential security issues or anomalies related to TLS connections.

    8. Secure Other Communication Channels
    - Ensure that other communication channels your client applications use, such as APIs or data transfers, also utilize TLS encryption.
    - Implement appropriate encryption and security measures to protect sensitive data during transit in all communication channels.
  "
  desc  'fix', "
    QLDB endpoints are HTTPS only.

    1. Add an explicit deny for requests where `aws:SecureTransport` is false, so the
       property is enforced rather than assumed.
    2. Confirm clients use a current AWS SDK or the QLDB driver and have not disabled
       certificate verification.
    3. Apply the same condition to the VPC endpoint policy where one is in use.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag nist_r4:               ['SC-8']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '11.4'
  tag cis_rid:               '11.4'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-1104r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('redshift')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("REDSHIFT out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe aws_redshift_compliance(regions: input('scan_regions')) do
    its('clusters_without_in_transit_encryption') { should be_empty }
  end
end
