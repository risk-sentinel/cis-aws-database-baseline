# encoding: UTF-8

control 'C-10.7' do
  title 'Ensure Regular Updates and Patches are Installed'
  desc  "
    Stay updated with the latest security patches and updates provided by AWS for Amazon Timestream. Follow AWS security best practices and recommendations to ensure your Timestream implementation remains secure.
  "
  desc  'rationale', "
    Stay updated with the latest security patches and updates provided by AWS for Amazon Timestream. Follow AWS security best practices and recommendations to ensure your Timestream implementation remains secure.
  "
  desc  'check', "
    1. Stay Informed about Updates
    Stay updated with the latest announcements and releases related to Amazon Timestream.
    Subscribe to AWS notifications, blogs, and forums to learn about new features, enhancements, and security patches.

    2. Review AWS Documentation
    Regularly review the official AWS documentation for Amazon Timestream.
    Pay attention to any updates or recommendations related to security, performance, and best practices.

    3. Implement a Patch Management Process
    Establish a patch management process specific to Amazon Timestream within your organization.
    Define roles and responsibilities for managing patches, including testing and deployment procedures.

    4. Test Patches in a Non-Production Environment
    Before deploying patches in production, create a non-production environment to test the patches.
    Set up a replica or a sandbox environment that resembles your production environment.
    Test the patches thoroughly to ensure they do not introduce compatibility issues or adverse effects.

    5. Schedule Patching Maintenance Windows
    Identify suitable maintenance windows to apply patches to your Timestream resources.
    Consider the impact on system availability and plan the maintenance window accordingly.
    Coordinate with relevant teams and stakeholders to ensure minimal disruption during the patching process.

    6. Apply Patches
    Once you have successfully tested the patches in the non-production environment and scheduled a maintenance window.
    Apply the patches to your production Timestream resources.
    Follow the recommended patching procedures provided by AWS in the documentation.
    Ensure you follow any specific instructions or requirements for applying patches to Timestream.

    7. Verify Patch Deployment
    After applying patches, monitor the Timestream resources to ensure they function as expected.
    Conduct thorough testing to validate that the patched resources operate correctly and have not introduced any issues.

    8. Regularly Monitor for Updates
    Continuously monitor for new updates, patches, and security bulletins related to Amazon Timestream.
    Stay informed about any vulnerabilities or critical patches that require immediate attention.
    Adjust your patch management process and schedule to incorporate new updates and releases.

    9. Automate Patch Management (Optional)
    Consider automating the patch management process using AWS tools or third-party solutions.
    Implement automation scripts or systems that handle patch deployments, testing, and monitoring.
  "
  desc  'fix', "
    Timestream is fully managed - there is no engine version to patch - so this
    control is about the parts you do own.

    1. Keep the AWS SDK and any Timestream client library in the application's
       dependency scanning, and update on the same cycle as other dependencies.
    2. Patch the compute that writes and reads (Lambda runtime, container base image,
       EC2 host) - that is where an unpatched vulnerability would actually sit.
    3. Subscribe to AWS Health Dashboard notifications for the service so required
       client-side changes, such as endpoint or TLS policy updates, are seen.
    4. Record the review cycle; this control is satisfied by evidence of that process
       rather than by a service setting.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '10.7'
  tag cis_rid:               '10.7'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-1007r1_rule'
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
  # manifest or SAF attestation must back it). Per-control override: c_10_7_evidence_uri.
  reason       = 'Amazon Timestream is a fully-managed service; AWS handles all engine updates and patches transparently per the AWS shared-responsibility model (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)'
  uri          = input('c_10_7_evidence_uri', value: attestation_uri(:leveraged, 'aws-soc2-type2', ext: 'json'))
  max_age_days = input('leveraged_evidence_max_age_days', value: 365)

  if uri.to_s.empty?
    describe 'C-10.7 AWS shared-responsibility evidence (no leveraged source configured)' do
      skip "inherited-from-aws: #{reason} Set leveraged_evidence_base / c_10_7_evidence_uri to the pulled AWS " \
           "evidence manifest (SOC 2 / FedRAMP / ISO), or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-10.7 AWS shared-responsibility leveraged evidence (#{uri})" do
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
