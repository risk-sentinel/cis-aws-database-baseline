# encoding: UTF-8

control 'C-9.6' do
  title 'Ensure Security Configurations are Reviewed Regularly'
  desc  "
    This helps by removing or updating any IAM roles, security networks, encryption settings, audit logging, and authentication. By updating or removing a few things from these lists it helps tighten security and ensures that the users do not have excessive permissions.
  "
  desc  'rationale', "
    This helps by removing or updating any IAM roles, security networks, encryption settings, audit logging, and authentication. By updating or removing a few things from these lists it helps tighten security and ensures that the users do not have excessive permissions.
  "
  desc  'check', "
    1. Establish a Security Review Schedule
    - Determine a regular schedule for reviewing and updating the security configuration of your Amazon Neptune environment.
    - Consider factors such as the frequency of changes, compliance requirements, and industry best practices to determine the appropriate review interval.

    2. Monitor AWS Security Bulletins
    - Stay informed about AWS security updates and announcements related to Amazon Neptune.
    - Regularly review AWS security bulletins and notifications to identify any security patches, updates, or new features relevant to your Neptune environment.
    - Take note of any security recommendations or best practices provided by AWS.

    3. Review IAM Roles and Policies
    - Access the AWS Identity and Access Management (IAM) console by navigating to `IAM` in the AWS Management Console.
    - Review the IAM roles and policies associated with your Neptune resources.
    - Ensure that the assigned permissions align with the principle of least privilege and reflect the current access requirements.
    - Update the IAM roles and policies as needed to adapt to changes in user access or security requirements.

    4. Review Security Groups and Network ACLs
    - Access the Amazon Neptune console by navigating to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/neptune/.
    - In the Neptune console, navigate to the `Connectivity & Security` or `Network & Security` section.
    - Review the security groups and network ACLs associated with your Neptune clusters.
    - Ensure that the inbound and outbound rules are up to date and aligned with your security requirements.
    - Remove any unnecessary or outdated rules and add new rules if required.

    5. Review Encryption Settings
    - Navigate to the `Configuration` section or relevant encryption settings in the Neptune console.
    - Review the encryption settings for both encryption at rest and encryption in transit.
    - Ensure that the appropriate encryption options and key management strategies are in place.
    - Consider rotating encryption keys periodically, following best practices and compliance requirements.

    6. Review VPC Configuration
    - Access the Amazon VPC console by navigating to `VPC` in the AWS Management Console.
    - Review the VPC configuration associated with your Neptune clusters.
    - Ensure the subnets, routing tables, and VPC peering settings are configured correctly.
    - Verify that the network architecture provides your Neptune resources' desired isolation and connectivity.

    7. Conduct Security Assessments
    - Periodically conduct security assessments and penetration testing on your Neptune environment.
    - Engage security experts or use appropriate security tools to identify vulnerabilities, weaknesses, or misconfigurations.
    - Analyze the assessment results and take necessary actions to remediate any security issues or risks.

    8. Stay Up to Date with Best Practices
    - Continuously educate yourself and your team on the latest security best practices for Amazon Neptune.
    - Stay informed about emerging security threats and vulnerabilities.
    -Regularly review AWS documentation, security blogs, and other relevant resources to enhance your understanding and implementation of security practices.
  "
  desc  'fix', "
    Review on a defined cycle, and record it.

    1. Re-check at each review: subnet placement and security group rules, KMS key,
       `neptune_enforce_ssl`, IAM database authentication, audit logging, backup
       retention, and engine version.
    2. Use AWS Config or Security Hub to catch drift between reviews.
    3. Record the date, reviewer, changes and accepted exceptions; that record is the
       evidence for this control.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '9.6'
  tag cis_rid:               '9.6'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0906r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('neptune')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("NEPTUNE out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  status, last_date, age_days = db_security_review_status
  msg = db_security_review_failure_message(status, last_date, age_days, 'Neptune')
  describe 'Neptune security-configuration review cadence (CIS 9.6)' do
    it 'must be current within db_security_review_cadence_days' do
      expect(status).to eq(:current), msg
    end
  end
end
