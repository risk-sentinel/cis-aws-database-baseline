# encoding: UTF-8

control 'C-2.4' do
  title 'Ensure IAM Roles and Policies are Created'
  desc  "
    AWS Identity and Access Management (IAM) helps manage access to AWS resources. While you cannot directly associate IAM roles with Amazon Aurora instances, you can use IAM roles and policies to define which AWS IAM users and groups have management permissions for Amazon RDS resources and what actions they can perform. Here is a guide:

    Individual creates IAM roles and polices that define specific permission given to that role. This determines what the identity or instance can and cannot do.
  "
  desc  'rationale', "
    AWS Identity and Access Management (IAM) helps manage access to AWS resources. While you cannot directly associate IAM roles with Amazon Aurora instances, you can use IAM roles and policies to define which AWS IAM users and groups have management permissions for Amazon RDS resources and what actions they can perform. Here is a guide:

    Individual creates IAM roles and polices that define specific permission given to that role. This determines what the identity or instance can and cannot do.
  "
  desc  'check', "
    1. Sign in to AWS Management Console 
    - If you do not already have an AWS account, you will need to create one at https://aws.amazon.com.

    2. Navigate to IAM Dashboard
    - Navigate to the IAM service once logged in to the AWS Management Console.
    - This is under the `Security, Identity, & Compliance` category.

    3. Create a New IAM Role 
    - In the IAM Dashboard, find the `Roles` section on the left-side navigation pane and click on it. Then, click on the `Create Role` button.

    4. Select the Service that will Use the Role 
    - Choose `RDS` as the AWS service that will use this new role, then click `Next: Permissions`.

    5. Attach Policy 
    - In the next screen, you can attach policies defining this role's permissions. You can use the filter to find existing policies like `AmazonRDSFullAccess` or `AmazonRDSReadOnlyAccess`. 
    - Select the appropriate policy and then click `Next: Tags`.

    6. Add Tags (Optional) 
    - You can add metadata to the role by attaching tags as key-value pairs. This is optional, and you can proceed to the next step if you do not wish to add tags.

    7. Review
    - Provide a name and a description for the role. Review the role and then click `Create Role`.

    8. Creating IAM Policy (Optional) 
    - You can create a custom IAM policy if the predefined policies do not meet your requirements.
    - Navigate to `Policies` in the IAM dashboard and click `Create Policy`. 
    - Use the visual editor or JSON editor to define the permissions. 
    - Once done, click `Review Policy`, give it a name and a description, and click `Create Policy`.
    - You can then attach this custom policy to the IAM role.

    9. Assign the IAM Role to an IAM User or Group 
    To assign the newly created role to an IAM User or Group.
    - Navigate to the user or group in the IAM dashboard.
    - Click `Add permissions`.
    - Then `Attach existing policies directly`. 
    - Use the filter to find your new role and select it. 
    - Click `Next: Review` and then `Add permissions`.
  "
  desc  'fix', "
    Give each consumer a role scoped to the cluster it uses, rather than a shared
    policy granting broad `rds:*`.

    1. Create an IAM role per application, trusted by that workload's compute
       identity, and attach a policy naming the specific cluster resource ARNs.
    2. For database sign-in, enable IAM database authentication and grant
       `rds-db:connect` against a specific `dbuser/` resource rather than a
       wildcard:

        ```
        aws rds modify-db-cluster --db-cluster-identifier <cluster-id> --enable-iam-database-authentication --apply-immediately
        ```

    3. Keep administrative permissions (`rds:Delete*`, `rds:Modify*`) in a separate
       role that applications do not assume.
    4. Review with IAM Access Analyzer for unused permissions, and remove what the
       workload has not exercised.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '2.4'
  tag cis_rid:               '2.4'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0204r1_rule'
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

  describe aws_rds_cluster_compliance(regions: input('scan_regions'), engines: input('rds_engines')) do
    its('clusters_without_iam_role_attached') { should be_empty }
  end
end
