# encoding: UTF-8

control 'C-5.10' do
  title 'Ensure Security Configurations are Reviewed Regularly'
  desc  "
    Regularly updating and reviewing the security configuration of your Amazon Keyspaces environment helps ensure that your database is protected against potential vulnerabilities and aligned with your security requirements.
  "
  desc  'rationale', "
    Regularly updating and reviewing the security configuration of your Amazon Keyspaces environment helps ensure that your database is protected against potential vulnerabilities and aligned with your security requirements.
  "
  desc  'check', "
    1. Sign in to the AWS Management Console
    - Sign in to the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon Keyspaces Console
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/keyspaces/.

    3. Select the Keyspace
    - Choose the Keyspace (database) for which you want to update and review the security configuration. 
    - Click on the Keyspace name to access its details page.

    4. Review IAM Roles and Permissions
    - In the Keyspace details page, click on the `Configuration` tab.
    - Under the `Authentication and access control` section, review the IAM roles and permissions associated with the Keyspace.
    - Ensure that the IAM roles have appropriate permissions and follow the principle of least privilege.
    - Review the IAM policies and make any necessary updates to align with your security requirements.

    5. Review Network Security
    - In the Keyspace details page, click on the `Configuration` tab.
    - Under the `Network & Security` section, review the VPC, subnets, security groups, and network ACLs associated with the Keyspace.
    - Ensure that the VPC and subnet configurations align with your security requirements.
    - Review the security group rules and network ACL rules to ensure they restrict access to necessary ports, IP ranges, and protocols.
    - Make any necessary updates to tighten the network security settings.

    6. Review Encryption Settings
    - In the Keyspace details page, click on the `Configuration` tab.
    - Under the `Encryption` section, review the encryption settings for the Keyspace.
    - Ensure that encryption at rest and in transit are enabled and the appropriate encryption options are chosen.
    - Review any customer-managed keys used for encryption and verify their configurations.

    7. Review Access Control
    - In the Keyspace details page, click on the `Configuration` tab.
    - Under the `Authentication and access control` section, review the Access Control Lists (ACLs) for the Keyspace.
    - Ensure the ACLs define appropriate access permissions at the table and row levels.
    - Review the ACL rules and make any necessary updates to align with your security policies and access requirements.

    8. Review Audit Logging
    - In the Keyspace details page, click on the `Configuration` tab.
    - Review the Keyspace's logging configuration under the `Logging` section.
    - Ensure the logs are captured and stored in CloudWatch Logs as expected.
    - Please review the log retention settings and y that they comply with your retention policies.

    9. Regularly Monitor Security Bulletins
    - Stay updated with AWS security bulletins, advisories, and best practices.
    - Monitor AWS security announcements and subscribe to relevant security notifications.
    - Regularly review and apply security patches, updates, and recommended configuration changes for Amazon Keyspaces.
  "
  desc  'fix', "
    Review on a defined cycle, and record it.

    1. Confirm at each review that encryption in transit and at rest are still on,
       the user group or AUTH configuration is unchanged, and no security group rule
       has been widened.
    2. Re-check that snapshots exist, are retained for the agreed period, and are
       encrypted.
    3. Record the date, reviewer, findings and accepted exceptions. This control is
       satisfied by that record, not by a live setting.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '5.10'
  tag cis_rid:               '5.10'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0510r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('elasticache')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("ELASTICACHE out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  status, last_date, age_days = db_security_review_status
  msg = db_security_review_failure_message(status, last_date, age_days, 'ElastiCache')
  describe 'ElastiCache security-configuration review cadence (CIS 5.10)' do
    it 'must be current within db_security_review_cadence_days' do
      expect(status).to eq(:current), msg
    end
  end
end
