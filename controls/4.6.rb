# encoding: UTF-8

control 'C-4.6' do
  title 'Ensure DynamoDB Streams and AWS Lambda for Automated Compliance Checking is Enabled'
  desc  "
    Enabling DynamoDB Streams and integrating AWS Lambda allows you to automate compliance checking and perform actions based on changes made to your DynamoDB data.

    Enabling the DynamoDB with AWS Lambda allows the individual to either use an existing or create a new execution role that allows Lambda to access DynamoDB and write logs.
  "
  desc  'rationale', "
    Enabling DynamoDB Streams and integrating AWS Lambda allows you to automate compliance checking and perform actions based on changes made to your DynamoDB data.

    Enabling the DynamoDB with AWS Lambda allows the individual to either use an existing or create a new execution role that allows Lambda to access DynamoDB and write logs.
  "
  desc  'check', "
    1. Open DynamoDB Console
    - Sign in to the AWS Management Console and open the DynamoDB console at https://console.aws.amazon.com/dynamodb/.

    2. Create or Select a DynamoDB Table
    - You can create a new DynamoDB table or select an existing one to enable DynamoDB Streams.

    3. Enable DynamoDB Streams
    - In the DynamoDB console, select your table.
    - Click on the `Overview` tab.
    - Under the `DynamoDB Streams` section, click on `Manage stream`.
    - In the `Manage stream` dialog, choose `Enable` and select the desired view type (e.g., `New and old images`).
    - Click `Enable`.

    4. Create an AWS Lambda Function
    - Open the AWS Management Console and navigate to the Lambda service at https://console.aws.amazon.com/lambda/.
    - Click `Create function` to create a new Lambda function.
    - Choose a function name, runtime (e.g., Node.js, Python), and other basic settings.
    - Under `Permissions`, choose an existing or create a new execution role that allows Lambda to access DynamoDB and write logs.
    - Click `Create function` to create the Lambda function.

    5. Configure AWS Lambda with DynamoDB Stream
    - Scroll down to the `Designer` section in the Lambda function editor.
    - Click on `Add trigger`.
    - Select `DynamoDB` from the trigger list.
    - In the `Configure triggers` dialog, choose the DynamoDB table and the stream that you enabled in the previous step.
    - Define the batch size and starting position, if applicable.
    - Click \"Add\".

    6. Write Lambda Function Code for Compliance Checking
    - In the Lambda function editor, scroll up to the code editor section.
    - Write your compliance-checking logic in the selected runtime language (e.g., Node.js, Python).
    - The code should handle the incoming DynamoDB stream records and perform the necessary compliance checks.
    - If needed, you can use the AWS SDKs or other libraries to interact with DynamoDB or other AWS services.

    7. Configure Lambda Function Settings
    - Scroll down to the `Function overview` section.
    - Configure the memory, timeout, and other settings as per your requirements.
    - Click `Save` to save the Lambda function.

    8. Test the Compliance Checking
    - You can test the compliance checking by changing the DynamoDB table and observing the Lambda function's behavior through the CloudWatch logs or other desired actions performed by the function.
  "
  desc  'fix', "
    Use the stream as a change feed so configuration and data changes are inspected
    as they happen rather than at the next audit.

        ```
        aws dynamodb update-table --table-name <table> --stream-specification StreamEnabled=true,StreamViewType=NEW_AND_OLD_IMAGES
        aws lambda create-event-source-mapping --function-name <function> --event-source-arn <stream-arn> --starting-position LATEST
        ```

    1. `NEW_AND_OLD_IMAGES` is what lets the consumer see what changed rather than
       only the resulting state.
    2. Give the function a dead-letter queue and alarm on iterator age. A consumer
       that silently falls behind produces the appearance of checking without the
       substance.
    3. Scope the function's role to the stream and its outputs only.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '4.6'
  tag cis_rid:               '4.6'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0406r1_rule'
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
    its('tables_without_streams') { should be_empty }
  end
end
