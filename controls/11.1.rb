# encoding: UTF-8

control 'C-11.1' do
  title 'Ensure to Implement Identity and Access Management (IAM)'
  desc  "
    This control is important because by having IAM roles implemented in the database it only allows certain people who are authenticated into the database to modify the database and would not give access to unauthorized personnel. This ensures that the data is being protected from any threat actor.
  "
  desc  'rationale', "
    This control is important because by having IAM roles implemented in the database it only allows certain people who are authenticated into the database to modify the database and would not give access to unauthorized personnel. This ensures that the data is being protected from any threat actor.
  "
  desc  'check', "
    1. Understand IAM and QLDB Integration
    - Familiarize yourself with IAM and its role in controlling access to AWS services, including QLDB.
    - Understand how IAM policies define permissions and access control rules for QLDB resources.

    2. Define IAM Users and Groups
    - Identify the users and groups that will need access to QLDB.
    - Create IAM user accounts for individuals who require direct access to QLDB.
    - Create IAM groups to organize users based on their roles or responsibilities logically.

    3. Define IAM Policies
    - Determine the permissions and actions users and groups need to perform on QLDB resources.
    - Create custom IAM policies or leverage existing IAM-managed policies to define these permissions.
    - Consider the principle of least privilege and grant only the necessary permissions for each user or group.

    4. Attach IAM Policies to Users and Groups
    - Associate the appropriate IAM policies with the IAM users and groups.
    - Ensure that each user or group has the necessary permissions to perform their tasks on QLDB.
    - Regularly review and update the assigned policies as access requirements evolve.

    5. Leverage IAM Roles
    - Identify AWS services or applications that require access to QLDB.
    - Create IAM roles to provide temporary credentials and permissions for these services.
    - Define trust relationships and establish the necessary permissions in the IAM role policies.

    6. Enable IAM Database Authentication
    - Configure IAM database authentication for QLDB to allow users to authenticate using their IAM credentials.
    - Enable the appropriate IAM authentication option in the QLDB configuration.
    - Configure your applications or clients to use IAM credentials when connecting to QLDB.

    7. Test IAM Access
    - Use IAM user credentials to log in and test the access to QLDB.
    - Verify that users can perform their intended actions based on their assigned IAM policies.
    - Test IAM roles and authentication for applications or services requiring access to QLDB.

    8. Monitor and Audit IAM Activity
    - Monitor IAM activity logs using AWS CloudTrail.
    - Set up appropriate CloudTrail trails to capture IAM-related events and API calls.
    - Regularly review IAM logs for any unauthorized access attempts or suspicious activities.

    9. Regularly Review and Update IAM Configuration
    - Periodically review the IAM policies, users, groups, and roles associated with QLDB.
    - Ensure access is granted based on business requirements and follows the principle of least privilege.
    - Remove or update IAM configurations when users or roles are no longer required.
  "
  desc  'fix', "
    Before hardening, confirm the service's lifecycle status. Amazon QLDB has been
    announced for end of support, so for most adopters the correct remediation is a
    migration plan to a supported ledger or an Aurora PostgreSQL design, not a
    long-term investment in this configuration. Verify the current date against the
    published schedule.

    Where the ledger remains in use:

    1. Grant access through IAM roles scoped to the specific ledger ARN, with
       `qldb:SendCommand` for data-plane access separated from administrative
       actions.
    2. Keep `qldb:DeleteLedger` and `qldb:UpdateLedger` in an administrative role no
       application assumes.
    3. Enable deletion protection on the ledger.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '11.1'
  tag cis_rid:               '11.1'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-1101r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('redshift')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("REDSHIFT out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe aws_redshift_compliance(regions: input('scan_regions')) do
    its('clusters_without_iam_roles') { should be_empty }
  end
end
