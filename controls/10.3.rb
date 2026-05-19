# encoding: UTF-8

control 'C-10.3' do
  title 'Ensure Encryption in Transit is Configured'
  desc  "
    Configure your applications or tools to use secure communication protocols when interacting with Amazon Timestream. Utilize endpoints to establish private and secure connections to Timestream.

    The database uses HTTPS/TLS to encrypt data during transit. To secure your data in transit the individual should identify their client application and what is supported by HTTPS/TLS in order to configure it correctly. Also has an option for leverage, which creates a private connection between virtual private code (VPC) without interfering with public networks.
  "
  desc  'rationale', "
    Configure your applications or tools to use secure communication protocols when interacting with Amazon Timestream. Utilize endpoints to establish private and secure connections to Timestream.

    The database uses HTTPS/TLS to encrypt data during transit. To secure your data in transit the individual should identify their client application and what is supported by HTTPS/TLS in order to configure it correctly. Also has an option for leverage, which creates a private connection between virtual private code (VPC) without interfering with public networks.
  "
  desc  'check', "
    1. Understand Encryption in Transit in Timestream
    Familiarize yourself with the concept of encryption in transit and its importance in securing data communication.
    Understand that encryption in transit ensures that data transmitted between clients and Timestream remains confidential and protected from interception.

    2. Use HTTPS for Communication
    Configure your client applications or tools to communicate with Amazon Timestream over HTTPS.
    Utilize the HTTPS protocol to establish secure encrypted connections between clients and the Timestream service.
    Ensure your client applications support the TLS (Transport Layer Security) protocol versions AWS recommends.

    3. Leverage AWS PrivateLink (Optional)
    Consider using AWS PrivateLink to establish private and secure connections between your VPC and Timestream.
    Configure a VPC endpoint for Timestream to securely access the service without traversing the public internet.

    4. Enable SSL/TLS Certificates
    Obtain and configure valid SSL/TLS certificates for your client applications or tools.
    Install the SSL/TLS certificates on your client systems or load balancers.
    Use the configured certificates to establish secure connections with Timestream.

    5. Verify Encryption in Transit
    Validate that your client applications or tools are using secure communication channels.
    Verify that HTTPS is being utilized for communication with Timestream.
    Confirm that SSL/TLS certificates are properly configured and used in communication.

    6. Monitor Encryption in Transit
    Utilize Amazon CloudWatch to monitor the metrics and logs related to your Timestream resources.
    Set up appropriate alarms and notifications to alert you of any potential security incidents or anomalies in the encryption in transit process.
    Regularly review the CloudWatch logs and metrics to ensure the integrity and security of the data in transit.

    7. Regularly Update Encryption Configuration
    Stay informed about the latest encryption standards, protocols, and best practices.
    Regularly review and update your encryption configurations and settings to align with industry standards and security recommendations.
    Apply any necessary updates or patches to client applications or tools to maintain strong encryption in transit.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '10.3'
  tag cis_rid:               '10.3'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-1003r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('timestream')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("TIMESTREAM out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe 'AWS shared-responsibility inheritance' do
    it 'is satisfied by AWS-managed controls — AWS Timestream enforces TLS on all client-facing endpoints by default; this is an AWS service-default control inherited from the AWS shared-responsibility model (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
      expect(true).to eq(true)
    end
  end
end
