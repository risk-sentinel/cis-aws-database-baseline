# encoding: UTF-8

control 'C-10.9' do
  title 'Ensure to Review and Update the Security Configuration'
  desc  "
    Conduct regular security reviews and assessments of your Amazon Timestream implementation. Evaluate access permissions, encryption settings, and security controls to ensure they align with your organization's security requirements.

    By regularly reviewing security configuration it helps the businesses to detect any threat they might be hindering and address the threat in a timely manner.
  "
  desc  'rationale', "
    Conduct regular security reviews and assessments of your Amazon Timestream implementation. Evaluate access permissions, encryption settings, and security controls to ensure they align with your organization's security requirements.

    By regularly reviewing security configuration it helps the businesses to detect any threat they might be hindering and address the threat in a timely manner.
  "
  desc  'check', "
    1. Understand Security Best Practices
    Familiarize yourself with the security best practices and recommendations provided by AWS for Timestream.
    Stay updated with the latest security guidelines and recommendations from AWS.

    2. Review IAM Policies
    Regularly review the IAM policies associated with Timestream resources.
    Ensure that the assigned IAM policies provide the necessary permissions for users and roles while adhering to the principle of least privilege.

    3. Audit User Access
    Periodically review the list of users and roles that have access to Timestream.
    Remove any unnecessary or unused accounts or permissions to minimize the attack surface.

    4. Monitor Access Patterns
    Utilize AWS CloudTrail and Amazon CloudWatch logs to monitor access patterns and activities related to Timestream.
    Set up alerts and notifications to detect any suspicious or unauthorized access attempts.

    5. Implement Security Controls
    Continuously assess and evaluate the security controls in place for Timestream.
    Implement additional security measures, such as VPC peering, security groups, or network ACLs, to further secure access to Timestream resources.

    6. Regularly Review Security Group Rules
    Regularly review the security group rules associated with Timestream instances.
    Remove any unnecessary open ports or protocols to minimize potential attack vectors.

    7. Stay Informed about Security Updates
    Keep track of security updates, patches, and new features released by AWS for Timestream.
    Stay informed about any security vulnerabilities or fixes related to Timestream.

    8. Conduct Security Assessments
    Perform periodic security assessments on your Timestream implementation, including vulnerability and penetration testing.
    Identify and remediate any security vulnerabilities or weaknesses discovered during the assessments.

    9. Stay Compliant
    Regularly review and update your security configurations to meet compliance requirements and industry standards.
    Stay informed about any changes in compliance regulations that may impact your Timestream environment.

    10. Educate and Train
    Provide regular security awareness training to users and administrators working with Timestream.
    Ensure that everyone involved understands their security responsibilities and follows security best practices.
  "
  desc  'fix', "
    Review on a defined cycle, and record it.

    1. Re-check at each review: IAM policies against actual usage, the KMS key and
       its grants, VPC endpoint and endpoint policy, retention settings for both
       stores, and CloudTrail coverage.
    2. Pay attention to table-level access as new tables are added - a new table
       created outside the review inherits no scoping.
    3. Record the date, reviewer, findings and accepted exceptions as the evidence.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '10.9'
  tag cis_rid:               '10.9'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-1009r1_rule'
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

  status, last_date, age_days = db_security_review_status
  msg = db_security_review_failure_message(status, last_date, age_days, 'Timestream')
  describe 'Timestream security-configuration review cadence (CIS 10.9)' do
    it 'must be current within db_security_review_cadence_days' do
      expect(status).to eq(:current), msg
    end
  end
end
