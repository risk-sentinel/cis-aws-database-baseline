# encoding: UTF-8

control 'C-7.11' do
  title 'Ensure to Conduct Security Assessments'
  desc  "
    Periodically perform security assessments, including vulnerability assessments and penetration testing, to identify and address any security weaknesses. Review your security configuration against best practices and industry standards.

    This helps ensure that any vulnerabilities that might lie dormant be addressed promptly, which would reduce the risk of a malicious attack. Reviewing and making sure the security policies are authentic ensures the safety of the organization data.
  "
  desc  'rationale', "
    Periodically perform security assessments, including vulnerability assessments and penetration testing, to identify and address any security weaknesses. Review your security configuration against best practices and industry standards.

    This helps ensure that any vulnerabilities that might lie dormant be addressed promptly, which would reduce the risk of a malicious attack. Reviewing and making sure the security policies are authentic ensures the safety of the organization data.
  "
  desc  'check', "
    1. Define the Scope of the Security Assessment
    - Clearly define the scope of the security assessment for your Amazon DocumentDB cluster.
    - Determine the objectives, areas of focus, and any specific compliance or security standards you must adhere to.

    2. Review Security Documentation
    - Familiarize yourself with the AWS security best practices and documentation related to Amazon DocumentDB.
    - Review the AWS Shared Responsibility Model and understand the security controls provided by AWS.

    3. Assess Network Security
    - Review the network security configuration of your Amazon DocumentDB cluster.
    - Ensure it is deployed within a secure Virtual Private Cloud (VPC) with appropriate security groups and network access control lists (ACLs).
    - Validate that the network traffic to and from the cluster is appropriately restricted based on your security requirements.

    4. Evaluate Encryption Configuration
    - Assess the encryption settings for your Amazon DocumentDB cluster.
    - Verify that encryption at rest is enabled and that the data stored in the cluster is encrypted.
    - Validate that encryption in transit is enforced, ensuring that all client connections to the cluster are encrypted using SSL/TLS.

    5. Review Access Control Mechanisms
    - Evaluate the access control mechanisms implemented for your Amazon DocumentDB cluster.
    - Ensure that appropriate Identity and Access Management (IAM) policies and roles are in place to control access to the cluster.
    - Review user accounts and their privileges, and validate that multi-factor authentication (MFA) is enforced for administrative access.

    6. Examine Audit Logging and Monitoring
    - Review the audit logging and monitoring configuration for your Amazon DocumentDB cluster.
    - Verify that audit logging is enabled, capturing relevant database activities and events.
    - Evaluate the monitoring setup using Amazon CloudWatch or other tools to detect unusual or suspicious activities.

    7. Assess Backup and Disaster Recovery
    - Evaluate the backup and disaster recovery mechanisms in place for your Amazon DocumentDB cluster.
    - Verify that automated backups are enabled and configured with an appropriate retention period.
    - Validate that manual backups can be performed and restored successfully.

    8. Perform Vulnerability Scanning and Penetration Testing (If Applicable)
    - If allowed and within the terms of service, perform vulnerability scanning and penetration testing on your Amazon DocumentDB cluster.
    - Conduct security assessments to identify any vulnerabilities or weaknesses that could be exploited.

    9. Document Findings and Remediation Plan
    - Document the findings of your security assessment, including any identified vulnerabilities or areas of improvement.
    - Develop a remediation plan that addresses the identified issues and outlines the necessary actions to enhance the security posture of your DocumentDB cluster.

    10. Implement Remediation Measures
    - Implement the necessary remediation measures based on your remediation plan.
    - Apply security patches, adjust configuration settings, and strengthen access controls as required.

    11. Regularly Repeat the Security Assessment
    - Conduct regular security assessments on your Amazon DocumentDB cluster to ensure ongoing compliance and identify new risks or vulnerabilities.
    - Stay updated with security best practices and apply any relevant updates or patches to your cluster.
  "
  desc  'fix', "
    Assess on a defined cycle, and record it.

    1. Cover at each assessment: network placement and security group rules,
       encryption at rest and TLS enforcement, user inventory and role assignments,
       audit logging, backup retention and restore testing, and engine version
       support.
    2. Include a review of who holds the master credential and whether it has been
       retrieved since the last assessment.
    3. Record the date, scope, findings, and remediation owners with dates. That
       record is the evidence for this control, since the state it asserts is
       procedural rather than API-visible.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '7.11'
  tag cis_rid:               '7.11'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0711r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('documentdb')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("DOCUMENTDB out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  # Converted from Skip-with-rationale to Pass-with-evidence via document_attestation
  # The bi-annual security-assessment / pen-test record is a
  # `boundary`-class doc (the boundary's own assessment). The URI defaults via
  # attestation_uri(:boundary, …), which resolves against boundary_docs_base and
  # returns '' when unset — so an unconfigured consumer SKIPs (preserving the
  # existing attestation rationale + `saf attest apply` fallback) rather than
  # FAILing. A per-control override (c_7_11_attestation_uri) still wins. Local var
  # is `uri` to avoid shadowing the attestation_uri helper method.
  uri          = input('c_7_11_attestation_uri', value: attestation_uri(:boundary, 'C-7.11'))
  max_age_days = input('c_7_11_attestation_max_age_days', value: 365)

  if uri.to_s.empty?
    ref = input('db_security_assessment_attestation_reference').to_s
    rationale = ref.empty? ?
      "attestation-required: bi-annual DocumentDB security assessment / pen-test record. Set " \
      "boundary_docs_base / c_7_11_attestation_uri to the assessment document, or supply a CMS-pattern " \
      "attestation via `saf attest apply` (populate db_security_assessment_attestation_reference to surface a reference here)." :
      "attestation-required: bi-annual DocumentDB security assessment / pen-test record (consumer attestation: #{ref}). " \
      "Set boundary_docs_base / c_7_11_attestation_uri to lift to Pass-with-evidence."
    describe 'DocumentDB security assessment cadence' do
      skip rationale
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "C-7.11 DocumentDB security-assessment attestation (#{uri})" do
      it 'is reachable (no connection error)' do
        expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}"
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
