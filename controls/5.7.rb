# encoding: UTF-8

control 'C-5.7' do
  title 'Ensure Security Configurations are Reviewed Regularly'
  desc  "
    Regularly updating and reviewing the security configuration of your Amazon ElastiCache clusters helps ensure that your clusters are protected against potential vulnerabilities and aligned with your security requirements.

    This ensures that the clusters are being regularly updated and protected from any potential vulnerabilities as well as meeting the security requirements.
  "
  desc  'rationale', "
    Regularly updating and reviewing the security configuration of your Amazon ElastiCache clusters helps ensure that your clusters are protected against potential vulnerabilities and aligned with your security requirements.

    This ensures that the clusters are being regularly updated and protected from any potential vulnerabilities as well as meeting the security requirements.
  "
  desc  'check', "
    1. Sign in to the AWS Management Console
    - Sign in to the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the ElastiCache Console
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/elasticache/.

    3. Select the ElastiCache Cluster
    - Choose the ElastiCache cluster you want to update and review the security configuration. Click on the cluster name to access its details page.

    4. Review IAM Policies
    - Navigate to the `Configuration` tab on the cluster details page.
    - Click on the `IAM Access` tab.
    - Review the IAM policies associated with the ElastiCache cluster and its resources.
    - Ensure that the IAM policies provide the least privileged access, granting only the necessary permissions to users and roles.
    - Update the IAM policies as required based on changes in access requirements or security best practices.

    5. Review Security Groups
    - Navigate to the `Configuration` tab on the cluster details page.
    - Click on the `Security Groups` tab.
    - Review the security groups associated with the ElastiCache cluster.
    - Ensure that the inbound and outbound rules of the security groups are configured correctly and restrict access to necessary ports and IP ranges.
    - Update the security group rules as needed to align with your security requirements.

    6. Review Encryption Settings
    - Navigate to the `Configuration` tab on the cluster details page.
    - Click on the `Encryption at Rest` tab.
    - Verify the encryption settings for the ElastiCache cluster.
    - Ensure that encryption at rest is enabled and using the appropriate encryption type (default AWS-managed key or customer-managed key).
    - Update the encryption settings if necessary to comply with your security policies.

    7. Review Network Security
    - Navigate to the `Configuration` tab on the cluster details page.
    - Click on the `Network & Security` tab.
    - Review the VPC, subnets, security groups, and network ACLs associated with the ElastiCache cluster.
    - Ensure that the VPC and subnet configurations align with your security requirements.
    - Update the network security settings as needed to maintain a secure network architecture.

    8. Review Access Control
    - Navigate to the `Configuration` tab on the cluster details page.
    - Click on the `Security` tab.
    - Review the authentication and access control settings for the ElastiCache cluster.
    - Ensure that the authentication method (no password, transit encryption, or encryption in transit) meets your security standards.
    - Update the access control settings as required to align with your security policies.

    9. Regularly Monitor Security Bulletins
    - Stay updated with AWS security bulletins, advisories, and best practices.
    - Regularly review security-related announcements from AWS.
    - Take necessary actions based on security recommendations, such as applying patches or configuration changes.
  "
  desc  'fix', "
    Review on a defined cycle, and record it.

    1. Re-check at each review: subnet placement, security group rules, encryption
       in transit and at rest, AUTH or RBAC configuration, engine version support,
       automatic upgrade setting, and backup retention.
    2. Use AWS Config or Security Hub to detect drift between reviews, so the review
       confirms a known state rather than discovering it.
    3. Record the date, the reviewer, what changed, and any accepted exception with
       its expiry. That record is the evidence for this control.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '5.7'
  tag cis_rid:               '5.7'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0507r1_rule'
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
  describe 'ElastiCache security-configuration review cadence (CIS 5.7)' do
    it 'must be current within db_security_review_cadence_days' do
      expect(status).to eq(:current), msg
    end
  end
end
