# encoding: UTF-8

control 'C-4.1' do
  title 'Ensure AWS Identity and Access Management (IAM) is in use'
  desc  "
    AWS Identity and Access Management (IAM) lets you securely control your users' access to AWS services and resources. To manage access control for Amazon DynamoDB, you can create IAM policies that control access to tables and data.

    IAM policies help you control and maintain access to Amazon DynamoDB as needed.
  "
  desc  'rationale', "
    AWS Identity and Access Management (IAM) lets you securely control your users' access to AWS services and resources. To manage access control for Amazon DynamoDB, you can create IAM policies that control access to tables and data.

    IAM policies help you control and maintain access to Amazon DynamoDB as needed.
  "
  desc  'check', "
    1. Open IAM Console
    - Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam/.

    2. Navigate to Policies
    - In the IAM console, in the navigation pane, choose `Policies`.

    3. Create Policy
    - Choose `Create policy`. 
    - You will be taken to the `Create policy` page.

    4. Choose Service
    - Click on `Choose a service`.
    - Type `DynamoDB` in the search box and select it.

    5. Configure Actions
    - Under the `Actions` section, select the actions you want to allow the user to perform. 
    - For instance, you can select `Read` to allow read actions like GetItem, Scan, Query, etc.

    6. Set Resources
    - Under the `Resources` section, you can specify which tables this policy applies to.
    - You can choose \"All resources\" or specify the ARN (Amazon Resource Name) of specific tables.

    7. Review Policy
    - Click on `Review policy`. 
    - Give your policy a name and description.
    - Then click `Create policy`.
    - Now, you have an IAM policy. 

    8. Attach Policy
    - Navigate to the `Users`, `Groups`, or `Roles` section in the IAM console. 
    - Choose an existing user, group, or role, or create a new one.
    - Once you've selected a user, group, or role, click `Add permissions`. 
    - Choose `Attach existing policies directly`.
    - Search for your created policy, select it, and click `Attach policy`.
    - With these steps, you have attached an IAM policy that controls access to DynamoDB resources.
  "
  desc  'fix', "
    1. Grant access through IAM roles assumed by the workload, never through
       long-lived user access keys, and never through the account root.
    2. Scope each policy to the specific table and index ARNs, and to the actions
       the workload performs. `dynamodb:*` on `*` is the common finding here.
    3. Separate read paths from write paths into different roles where the
       application allows it, so a compromised reader cannot mutate data.
    4. Run IAM Access Analyzer and remove permissions the workload has not used.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '4.1'
  tag cis_rid:               '4.1'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0401r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('dynamodb')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("DYNAMODB out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe aws_dynamodb_compliance(regions: input('scan_regions')) do
    its('tables_without_resource_policy') { should be_empty }
  end
end
