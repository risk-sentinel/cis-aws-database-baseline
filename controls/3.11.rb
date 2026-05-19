# encoding: UTF-8

control 'C-3.11' do
  title 'Ensure to Regularly Review Security Configuration'
  desc  "
    This helps by reviewing the database factors from database engine, review instance details, security networks, encryption settings, audit logging, and authentication. By updating or removing a few things from these lists it helps tighten security and ensures that the users do not have excessive permissions.
  "
  desc  'rationale', "
    This helps by reviewing the database factors from database engine, review instance details, security networks, encryption settings, audit logging, and authentication. By updating or removing a few things from these lists it helps tighten security and ensures that the users do not have excessive permissions.
  "
  desc  'check', "
    1. Sign into the AWS Management Console
    - Sign into the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon RDS Console
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/rds/.

    3. Select the RDS Instance 
    - Choose the Amazon RDS instance you want to review the security configuration. 
    - Click on the instance name to access its details page.

    4. Review the Database Engine Documentation
    - Refer to the documentation provided by the database engine vendor (e.g., MySQL, PostgreSQL, Oracle, SQL Server) to understand the security best practices and configuration options specific to the database engine you use on Amazon RDS.
    - Review the vendor's guidelines for securing the database engine and associated components.

    5. Review the Instance Details
    - In the instance details page, review the configuration settings related to security.
    - Security group associations: Ensure the appropriate security groups are assigned to the RDS instance to control inbound and outbound traffic.
    - IAM database authentication: Verify if IAM database authentication is enabled for enhanced security.
    - Encryption at rest: Confirm if encryption at rest is enabled using either AWS-managed keys or customer-managed keys.
    - Encryption in transit: Check if SSL/TLS encryption is enabled for secure data transmission.
    Backup and retention: Review the automated backup settings and retention period to ensure data recovery capability.

    6. Review Database User Privileges
    - Click `Users` in the Amazon RDS console menu.
    - Review the privileges assigned to database users.
    - Ensure that the least privileged access is implemented, granting only necessary privileges to each user or role.

    7. Review Audit and Logging Configuration
    - In the Amazon RDS console, navigate to the `Configuration` or `Monitoring & Logs` section.
    - Review the settings related to database audit logging and logging.
    - Ensure appropriate logs are enabled and configured to capture necessary information for security analysis and monitoring.

    8. Review Network Security
    - In the Amazon RDS console, navigate to the `Connectivity & Security` or `Security` section.
    - Review the network security settings, including the associated security groups and their rules.
    - Verify that only necessary ports are open, and access is restricted to trusted sources.

    9. Review and Address Security Recommendations
    - Periodically review the security recommendations provided by AWS through the Amazon RDS console or the AWS Trusted Advisor service.
    - Address any security recommendations promptly to ensure a secure configuration.

    10. Document and Update
    - Document the security configuration settings and any changes made during the review process.
    - Maintain an up-to-date inventory of the security controls and configurations implemented for your RDS instances.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '3.11'
  tag cis_rid:               '3.11'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0311r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('rds')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("RDS out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  status, last_date, age_days = db_security_review_status
  msg = db_security_review_failure_message(status, last_date, age_days, 'RDS')
  describe 'RDS security-configuration review cadence (CIS 3.11)' do
    it 'must be current within db_security_review_cadence_days' do
      expect(status).to eq(:current), msg
    end
  end
end
