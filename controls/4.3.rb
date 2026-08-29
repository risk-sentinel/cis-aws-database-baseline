# encoding: UTF-8

control 'C-4.3' do
  title 'Ensure DynamoDB Encryption at Rest'
  desc  "
    Encryption at rest in Amazon DynamoDB enhances the security of your data by encrypting it using AWS Key Management Service (AWS KMS) keys. Here is how to enable encryption at rest while creating a DynamoDB table.

    Once the user is in their AWS account, they should open the DynamoDB to create the table and enable encryption. A key would be required to be created to enable encryption. Only the authorized user would always have access to this key. Enabling encryption would keep the user's data private and stored securely, which would only allow them to access it with their key.
  "
  desc  'rationale', "
    Encryption at rest in Amazon DynamoDB enhances the security of your data by encrypting it using AWS Key Management Service (AWS KMS) keys. Here is how to enable encryption at rest while creating a DynamoDB table.

    Once the user is in their AWS account, they should open the DynamoDB to create the table and enable encryption. A key would be required to be created to enable encryption. Only the authorized user would always have access to this key. Enabling encryption would keep the user's data private and stored securely, which would only allow them to access it with their key.
  "
  desc  'check', "
    1. Open DynamoDB Console
    - Sign in to the AWS Management Console and open the DynamoDB console at https://console.aws.amazon.com/dynamodb/.

    2. Create DynamoDB Table
    - Click `Create table`. This will bring you to the `Create DynamoDB table` page.

    3. Specify Table Details
    - Enter a `Table name` and `Primary key`. 
    - The primary key consists of a partition key and, optionally, a sort key. 
    - Fill in these details according to your requirements.

    4. Enable Encryption
    - Under the `Settings` section, check the `Enable encryption at rest`. 
    - By default, DynamoDB uses an AWS-owned CMK to encrypt your data.
    - To use an AWS-managed CMK or a customer-managed CMK instead, select `AWS-managed CMK` or `Customer-managed CMK` from the dropdown menu, then choose the desired CMK.

    5. Create a Table
    - Click `Create`. 
    - This will create your DynamoDB table with encryption at rest enabled.

    Note:
    1. The setting for encryption at rest applies to all DynamoDB data associated with the table, including primary key data and indexes.
    2. If you need to apply encryption at rest to an existing table, you can modify the table settings. However, modifying settings on large tables could take time and impact performance during the transition.
    3. Ensure you have the necessary permissions in AWS KMS when choosing an AWS-managed CMK or a customer-managed CMK.
  "
  desc  'fix', "
    Tables are encrypted at rest by default with an AWS-owned key. Move to a
    customer-managed key where key access must be auditable and revocable:

        ```
        aws dynamodb update-table --table-name <table> --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=<kms-key-arn>
        ```

    1. A customer-managed key means CloudTrail records every decrypt, and revoking
       the key grant makes the data inaccessible - which is what makes it a control
       rather than a checkbox.
    2. Apply the same key choice to backups and to any global table replica; a
       replica in another Region uses a key in that Region.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-28', 'AC-8 a']
  tag ksi:                   ['KSI-SVC-SIN']
  tag nist_r4:               ['SC-28']
  tag cci:                   ['CCI-001199', 'CCI-000051']
  tag cis_number:            '4.3'
  tag cis_rid:               '4.3'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0403r1_rule'
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

  aws_dynamodb_tables.table_names.each do |name|
    describe aws_dynamodb_table(table_name: name) do
      it { should be_encrypted }
    end
  end
end
