# encoding: UTF-8

control 'C-4.4' do
  title 'Ensure DynamoDB Encryption in Transit'
  desc  "
    Use the SSL/TLS protocol to encrypt data in transit between your applications and DynamoDB.
    Amazon DynamoDB encrypts data in transit by default using Transport Layer Security (TLS) encryption. Here is a step-by-step guide on how to ensure encryption in transit for your DynamoDB:

    Amazon DynamoDB uses TLS to encrypt data during transit. To secure your data in transit the individual should identify their client application and what is supported by TLS to configure it correctly.
  "
  desc  'rationale', "
    Use the SSL/TLS protocol to encrypt data in transit between your applications and DynamoDB.
    Amazon DynamoDB encrypts data in transit by default using Transport Layer Security (TLS) encryption. Here is a step-by-step guide on how to ensure encryption in transit for your DynamoDB:

    Amazon DynamoDB uses TLS to encrypt data during transit. To secure your data in transit the individual should identify their client application and what is supported by TLS to configure it correctly.
  "
  desc  'check', "
    1. Access the DynamoDB Console
    - Sign in to the AWS Management Console and open the DynamoDB console at https://console.aws.amazon.com/dynamodb/.

    2. Create or Select a DynamoDB Table
    - You can create a new DynamoDB table or select an existing one to configure encryption in transit.

    3. Verify Encryption Settings
    - By default, DynamoDB encrypts data in transit using TLS. To ensure that encryption in transit is enabled:
    - In the DynamoDB console, select your table.
    - In the table details, navigate to the `Overview` tab.
    - Under the `Encryption` section, verify that \"Encryption at rest\" is enabled. This indicates that data is encrypted at rest.
    - Confirm that `Encryption in transit` is enabled. It should be enabled by default.

    4. Use SSL/TLS Endpoints for API Calls
    - To ensure that your API calls to DynamoDB are encrypted in transit, use SSL/TLS endpoints:
    - Use the appropriate SDK or AWS CLI in your application or code that interacts with DynamoDB.
    - By default, the SDKs and AWS CLI use the SSL/TLS endpoints provided by DynamoDB.
    - Verify that your code is configured to connect to DynamoDB using the appropriate SSL/TLS endpoint.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '4.4'
  tag cis_rid:               '4.4'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0404r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('dynamodb')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("DYNAMODB out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  # Inherited from AWS shared-responsibility — refactored from the expect(true)
  # stub to a real freshness check against SPARC's pulled AWS-evidence manifest
  # (sparc-validate#154). Defaults via attestation_uri(:leveraged, 'aws-soc2-type2'),
  # which resolves against leveraged_evidence_base; UNSET -> '' -> Skip (audit-
  # defensible per the ratified #154 §10.3 — no vacuous pass; a leveraged-systems
  # manifest or SAF attestation must back it). Per-control override: c_4_4_evidence_uri.
  reason       = 'AWS DynamoDB enforces TLS 1.2 on all client-facing endpoints by default; this is a service-default control inherited from the AWS shared-responsibility model (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)'
  uri          = input('c_4_4_evidence_uri', value: attestation_uri(:leveraged, 'aws-soc2-type2', ext: 'json'))
  max_age_days = input('leveraged_evidence_max_age_days', value: 365)

  if uri.to_s.empty?
    describe 'C-4.4 AWS shared-responsibility evidence (no leveraged source configured)' do
      skip "inherited-from-aws: #{reason} Set leveraged_evidence_base / c_4_4_evidence_uri to the pulled AWS " \
           "evidence manifest (SOC 2 / FedRAMP / ISO), or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-4.4 AWS shared-responsibility leveraged evidence (#{uri})" do
      it 'is reachable (no connection error)' do
        expect(doc.connection_error).to be_nil, "evidence unreachable: #{doc.connection_error}"
      end
      it 'exists' do
        expect(doc.exists?).to eq(true)
      end
      it "is current within #{max_age_days} days" do
        expect(doc.current?).to eq(true)
      end
    end
  end
end
