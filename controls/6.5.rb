# encoding: UTF-8

control 'C-6.5' do
  title 'Ensure Security Configurations are Reviewed Regularly'
  desc  "
    This helps by removing or updating any IAM roles, security networks, encryption settings, audit logging, and authentication. By updating or removing a few things from these lists it helps tighten security and ensures that the users do not have excessive permissions.
  "
  desc  'rationale', "
    This helps by removing or updating any IAM roles, security networks, encryption settings, audit logging, and authentication. By updating or removing a few things from these lists it helps tighten security and ensures that the users do not have excessive permissions.
  "
  desc  'check', "
    1. Sign into the AWS Management Console
    - Sign into the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon MemoryDB Console 
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/memorydb/.

    3. Select the Cluster
    - Choose the Amazon MemoryDB cluster for which you want to update and review the security configuration. 
    - Click on the cluster name to access its details page.

    4. Review IAM Roles and Permissions
    - In the cluster details page, navigate to the `Security` or `Access Control` section.
    - Review the IAM roles and permissions associated with the cluster.
    - Ensure that the IAM roles have appropriate permissions and follow the principle of least privilege.
    - Review the IAM policies and make any necessary updates to align with your security requirements.

    5. Review Network Security
    - In the cluster details page, navigate to the `Security` or `Network & Security` section.
    - Review the Virtual Private Cloud (VPC), subnets, security groups, and network ACLs associated with the cluster.
    - Ensure that the VPC and subnet configurations align with your security requirements.
    - Review the security group rules and network ACL rules to ensure they restrict access to necessary ports, IP ranges, and protocols.
    - Make any necessary updates to tighten the network security settings.

    6. Review Encryption Settings
    - In the cluster details page, navigate to the `Security` or `Encryption` section.
    - Review the encryption settings for the cluster.
    - Ensure that encryption at rest and in transit are enabled and the appropriate encryption options are chosen.
    - Review any customer-managed keys used for encryption and verify their configurations.

    7. Review Authentication and Access Control
    - In the cluster details page, navigate to the `Security` or `Access Control` section.
    - Review the authentication options and access control policies in place for the cluster.
    - Ensure that the authentication mechanisms and access control policies align with your security requirements.
    - Make any necessary updates to adapt to changing access requirements or security policies.

    8. Review Audit Logging
    - In the cluster details page, navigate to the `Monitoring` or `Logging` section.
    - Review the logging configuration for the cluster.
    - Ensure that the logs are captured and stored as expected.
    - Please review the log retention settings and verify that they comply with your retention policies.

    9. Regularly Monitor Security Bulletins
    - Stay updated with AWS security bulletins, advisories, and best practices.
    - Monitor AWS security announcements and subscribe to relevant security notifications.
    - Regularly review and apply security patches, updates, and recommended configuration changes for Amazon MemoryDB.
  "
  desc  'fix', "
    Review on a defined cycle, and record it.

    1. Confirm at each review: subnet placement and security group rules, the KMS
       key in use, TLS still enabled, ACL membership and each user's access string,
       engine version, and snapshot retention.
    2. Pay particular attention to ACL drift - users accumulate, and an access string
       widened for a one-off migration tends to stay widened.
    3. Record date, reviewer, changes and accepted exceptions as the evidence.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '6.5'
  tag cis_rid:               '6.5'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0605r1_rule'
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

  status, last_date, age_days = db_security_review_status
  msg = db_security_review_failure_message(status, last_date, age_days, 'MemoryDB')
  describe 'MemoryDB security-configuration review cadence (CIS 6.5)' do
    it 'must be current within db_security_review_cadence_days' do
      expect(status).to eq(:current), msg
    end
  end
end
