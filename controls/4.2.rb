# encoding: UTF-8

control 'C-4.2' do
  title 'Ensure Fine-Grained Access Control is implemented'
  desc  "
    Fine-Grained Access Control (FGAC) on Amazon DynamoDB allows you to control access to data at the row level. Using IAM policies, you can restrict access based on the content within the request. Here is how you can implement FGAC:

    Fine-Grained access control helps users to create and allow specific permission within that DB.
  "
  desc  'rationale', "
    Fine-Grained Access Control (FGAC) on Amazon DynamoDB allows you to control access to data at the row level. Using IAM policies, you can restrict access based on the content within the request. Here is how you can implement FGAC:

    Fine-Grained access control helps users to create and allow specific permission within that DB.
  "
  desc  'check', "
    1. Create an IAM Role
    - Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam/.
    - In the navigation pane, choose `Roles` and select `Create role`.
    - Choose `AWS service` as the type of trusted entity.
    - Choose `DynamoDB` as the service that will use this role, then click `Next: Permissions`.
    - On the `Attach permissions policies` page, choose `Next: Tags`. You do not need to attach a policy to this role yet.
    - On the `Add tags` page, choose `Next: Review`.
    - On the `Review` page, for `Role name`, enter a name for your role, such as DynamoDBFineGrainedAccessRole.
    - Choose `Create role`.

    2. Create an IAM Policy for Fine-Grained Access Control
    - In the navigation pane, choose `Policies` and select `Create policy`.
    - Choose the `JSON` tab.
    - Paste the following policy into the policy document field, replacing _`us-west-2`_, _`123456789012`_, _`myddbtable`_, _`HK`_, and _`RANGEK`_ with your own values: 
    ```
    {
        \"Version\": \"2012-10-17\",
        \"Statement\": [
            {
                \"Effect\": \"Allow\",
                \"Action\": [
                    \"dynamodb:GetItem\",
                    \"dynamodb:BatchGetItem\",
                    \"dynamodb:Query\",
                    \"dynamodb:PutItem\",
                    \"dynamodb:UpdateItem\",
                    \"dynamodb:DeleteItem\"
                ],
                \"Resource\": \"arn:aws:dynamodb: \",
                \"Condition\": {
                    \"ForAllValues:StringEquals\": {
                        \"dynamodb:LeadingKeys\": [\"${www.amazon.com:user_id}\"],
                        \"dynamodb:Attributes\": [
                            \" \",
                            \" \"
                        ]
                    },
                    \"StringEqualsIfExists\": {
                        \"dynamodb:Select\": \"SPECIFIC_ATTRIBUTES\"
                    }
                }
            }
        ]
    }
    ```
    In this policy:
    - `dynamodb:LeadingKeys` restrict access to only the items where the hash key value is the same as the user's ID.
    - `dynamodb:Attributes` restrict access to only the \"HK\" and \"RANGEK\" attributes of the items.
    - `dynamodb:Select` only allows the `SPECIFIC_ATTRIBUTES` operator.
    - Choose `Next: Tags`, add any tags if needed, and then choose `Next: Review`.
    - For `Name`, enter a name for your policy, such as DynamoDBFineGrainedAccessPolicy.
    - Choose `Create policy`.

    3. Attach the Policy to the Role
    - In the navigation pane, choose `Roles`.
    - Choose the role that you created in the previous step.
    - On the `Permissions` tab, choose `Attach policies`.
    - In the `Filter policies` search box, enter the policy name you created before.
    - Select the check box for your policy, then choose `Attach policy`.

    Note: Fine-grained access control is a powerful feature but can be complex to configure. Be sure to test your setup to ensure it works as expected thoroughly.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '4.2'
  tag cis_rid:               '4.2'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0402r1_rule'
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
