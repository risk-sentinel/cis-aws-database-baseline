# encoding: UTF-8

control 'C-10.1' do
  title 'Ensure Data Ingestion is Secure'
  desc  "
    This helps ensure that the system is updated with any potential vulnerabilities that might pose a threat to the organization. Helps authenticate the sources that are coming to the database and ensures that only authorized users have the credential to access the data.
  "
  desc  'rationale', "
    This helps ensure that the system is updated with any potential vulnerabilities that might pose a threat to the organization. Helps authenticate the sources that are coming to the database and ensures that only authorized users have the credential to access the data.
  "
  desc  'check', "
    1. Secure Data Sources
    Ensure that your data sources are protected with appropriate security measures.
    Implement secure network configurations, access controls, and authentication mechanisms for your data sources.
    Apply security patches and updates to your data source systems to prevent vulnerabilities.

    2. Use HTTPS or AWS Direct Connect
    When ingesting data into Timestream, use secure communication protocols such as HTTPS.
    Encrypt data in transit to protect it from unauthorized interception.
    Consider using AWS Direct Connect for a dedicated private network connection to Timestream, ensuring data privacy.

    3. Implement Client-Side Encryption
    Encrypt your data before sending it to Timestream using client-side encryption.
    Use industry-standard encryption algorithms and strong encryption keys to protect the confidentiality of your data.
    Store and manage the encryption keys securely using AWS Key Management Service (KMS).

    4. Authenticate Data Sources
    Implement authentication mechanisms for your data sources to ensure only authorized sources can ingest data into Timestream.
    Use mechanisms such as API keys, access tokens, or client certificates to verify the authenticity of the data source.
    Consider integrating with AWS Identity and Access Management (IAM) for centralized authentication and access control.

    5. Validate and Sanitize Data
    Implement data validation and sanitization mechanisms to prevent injection attacks or malformed data from being ingested into Timestream.
    Use input validation techniques and enforce data format requirements to ensure the integrity of the ingested data.
    Implement data quality checks to identify and handle anomalies or outliers.

    6. Monitor Data Ingestion
    Implement monitoring and logging for data ingestion processes.
    Regularly review logs and metrics related to data ingestion to detect anomalies or suspicious activities.
    Set up alarms and notifications for data ingestion failures or unexpected patterns.

    7. Regularly Update Data Ingestion Components
    Keep your data ingestion components, such as APIs, scripts, or connectors, up to date with the latest security patches and updates.
    Follow safe coding practices and stay informed about security vulnerabilities and fixes specific to your data ingestion tools.

    8. Implement Network Security Controls
    Use network security controls such as security groups, network ACLs, and VPC configurations to restrict access to your Timestream resources.
    Configure inbound and outbound traffic rules to allow only necessary network connections for data ingestion.
    Follow the principle of least privilege, granting access only to the required IPs or networks.
  "
  desc  'fix', "
    Constrain what may write, and how it reaches the service.

    1. Give each producer an IAM role scoped to the specific database and table ARNs
       with `timestream:WriteRecords` only - no read, no schema change.
    2. Reach Timestream over an interface VPC endpoint so ingestion does not traverse
       the internet:

        ```
        aws ec2 create-vpc-endpoint --vpc-id <vpc-id> --vpc-endpoint-type Interface --service-name com.amazonaws.<region>.timestream-ingest-cells --subnet-ids <subnet-id> --security-group-ids <sg-id>
        ```

    3. Deny requests where `aws:SecureTransport` is false, so TLS is enforced rather
       than assumed.
    4. Where data arrives via Kinesis or IoT Core, apply the same scoping to that
       pipeline's role - the weakest identity in the chain sets the exposure.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '10.1'
  tag cis_rid:               '10.1'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-1001r1_rule'
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

  # Inherited from AWS shared-responsibility — refactored from the expect(true)
  # stub to a real freshness check against the consumer's pulled AWS-evidence
  # manifest. Defaults via attestation_uri(:leveraged, 'aws-soc2-type2'),
  # which resolves against leveraged_evidence_base; UNSET -> '' -> Skip (audit-
  # defensible by design — no vacuous pass; a leveraged-systems
  # manifest or SAF attestation must back it). Per-control override: c_10_1_evidence_uri.
  reason       = 'AWS Timestream enforces TLS on all ingestion endpoints by default; this is an AWS service-default control inherited from the AWS shared-responsibility model (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)'
  uri          = input('c_10_1_evidence_uri', value: attestation_uri(:leveraged, 'aws-soc2-type2', ext: 'json'))
  max_age_days = input('leveraged_evidence_max_age_days', value: 365)

  if uri.to_s.empty?
    describe 'C-10.1 AWS shared-responsibility evidence (no leveraged source configured)' do
      skip "inherited-from-aws: #{reason} Set leveraged_evidence_base / c_10_1_evidence_uri to the pulled AWS " \
           "evidence manifest (SOC 2 / FedRAMP / ISO), or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-10.1 AWS shared-responsibility leveraged evidence (#{uri})" do
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
