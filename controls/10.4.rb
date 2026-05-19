# encoding: UTF-8

control 'C-10.4' do
  title 'Ensure Access Control and Authentication is Enabled'
  desc  "
    Utilize AWS Identity and Access Management (IAM) to control access to your Amazon Timestream resources. Define IAM policies that grant or deny permissions for specific Timestream actions and resources.

    Users should select whether they like to enable authentication. If they want to authenticate the user would be required to implement IAM roles would grant or deny permissions within that database. Users also have an option to enable multi-factor authentication, which adds an extra layer of security restricting access to unauthorized users.
  "
  desc  'rationale', "
    Utilize AWS Identity and Access Management (IAM) to control access to your Amazon Timestream resources. Define IAM policies that grant or deny permissions for specific Timestream actions and resources.

    Users should select whether they like to enable authentication. If they want to authenticate the user would be required to implement IAM roles would grant or deny permissions within that database. Users also have an option to enable multi-factor authentication, which adds an extra layer of security restricting access to unauthorized users.
  "
  desc  'check', "
    1. Understand AWS Identity and Access Management (IAM)
    Familiarize yourself with IAM, the AWS service used to manage access to AWS resources.
    Understand IAM users, groups, roles, policies, and permissions, essential for access control in Timestream.

    2. Create IAM Users, Groups, and Roles
    Access the AWS Management Console and navigate to the IAM service.
    Create IAM users, groups, and roles based on your organization's access control requirements for Timestream.
    Define appropriate permissions for these entities, limiting access to specific Timestream actions and resources.

    3. Assign IAM Policies
    Create IAM policies that define the desired level of access to Timestream.
    Associate these policies with the respective IAM users, groups, and roles created earlier.
    Ensure that the policies provide the necessary permissions for users to interact with Timestream resources.

    4. Use IAM Roles for External Applications
    If you have external applications or services accessing Timestream, create IAM roles specific to those applications.
    Define the necessary permissions in the IAM roles and grant them to the respective applications or services.
    Configure the applications or services to assume these IAM roles when accessing Timestream.

    5. Enable Multi-Factor Authentication (MFA)
    Enable MFA for IAM users who require access to Timestream.
    Configure MFA devices and enforce MFA usage for these users.
    MFA adds an extra layer of security by requiring an additional authentication factor during the login process.

    6. Implement AWS Identity Federation (Optional)
    Consider implementing AWS Identity Federation if you need to grant access to Timestream to users from external identity providers.
    Configure the necessary trust relationships and establish a federation between the external identity provider and AWS.
    Ensure that the federated users have the appropriate IAM policies and permissions for Timestream.

    7. Regularly Review and Update Access Controls
    Periodically review and update the IAM policies and permissions for Timestream.
    Remove unnecessary access permissions and ensure access controls align with your organization's security requirements.
    Monitor IAM activity logs and AWS CloudTrail to identify unauthorized access attempts or unusual activities.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '10.4'
  tag cis_rid:               '10.4'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-1004r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'operational'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('timestream')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("TIMESTREAM out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  ref = input('db_iam_attestation_reference').to_s
  rationale = ref.empty? ?
    "Requires manual review and attestation provided for this control (Timestream's per-table IAM policy granularity is consumer-policy-dependent; operators attest from their data-classification + per-table IAM policy review. Populate db_iam_attestation_reference input to surface the reference here)" :
    "Requires manual review and attestation provided for this control (consumer attestation: #{ref})"
  describe 'Timestream access control + authentication' do
    skip rationale
  end
end
