# encoding: UTF-8

control 'C-4.5' do
  title 'Ensure VPC Endpoints are configured'
  desc  "
    Using VPC endpoints with Amazon DynamoDB allows you to securely access DynamoDB resources within your Amazon Virtual Private Cloud (VPC). This keeps your traffic off the public internet.

    Using VPC endpoint in the DynamoDB helps ensure that the data is secured and that no external networks would have access to the network. It is a private network where the user has access to their desired availability zones and subnets.
  "
  desc  'rationale', "
    Using VPC endpoints with Amazon DynamoDB allows you to securely access DynamoDB resources within your Amazon Virtual Private Cloud (VPC). This keeps your traffic off the public internet.

    Using VPC endpoint in the DynamoDB helps ensure that the data is secured and that no external networks would have access to the network. It is a private network where the user has access to their desired availability zones and subnets.
  "
  desc  'check', "
    1. Open Amazon VPC Console
    - Sign in to the AWS Management Console and open the Amazon VPC console at https://console.aws.amazon.com/vpc/.

    2. Create a VPC Endpoint
    - In the Amazon VPC console, navigate to the `Endpoints` section in the left-side menu.
    - Click `Create Endpoint`.
    - Select your desired VPC in the `VPC` dropdown menu.
    - In the `Service category` section, choose `AWS services`.
    - In the `Filter Services` search box, enter `DynamoDB` and select `DynamoDB` from the results.
    - Choose your desired availability zone(s) and subnet(s).
    - Leave the default settings for other options or customize them according to your requirements.
    - Click `Create endpoint`.

    3. Update Route Tables
    - In the Amazon VPC console, navigate to the `Route Tables` section in the left-side menu.
    - Find the route table associated with your VPC or subnet from which you want to access DynamoDB.
    1. Edit the route table and add a route for the DynamoDB VPC endpoint.
    	- Destination: Enter the CIDR block of the DynamoDB VPC endpoint, typically in the form of `vpce-xxxxxx-xxxxxxx-xxxxxxx-xxxxxxx.vpce.amazonaws.com/32`.
    	- Target: Select the VPC endpoint ID from the dropdown menu.
    2. Save the changes to update the route table.

    4. Verify Connectivity
    To ensure that your VPC endpoint for DynamoDB is functioning correctly:
    - Launch an Amazon EC2 instance within your VPC or use an existing one.
    - Connect to the EC2 instance using SSH or other remote access methods.
    - From the EC2 instance, try to access DynamoDB using the SDK or CLI.
    - Ensure that the access to DynamoDB is successful and that data can be retrieved or modified.
  "
  desc  'fix', "
    Keep DynamoDB traffic on the AWS network rather than routing it through a NAT
    gateway to the public endpoint.

        ```
        aws ec2 create-vpc-endpoint --vpc-id <vpc-id> --service-name com.amazonaws.<region>.dynamodb --route-table-ids <rtb-id>
        ```

    1. DynamoDB uses a gateway endpoint, which is attached to route tables rather
       than to subnets, and costs nothing.
    2. Apply an endpoint policy naming the tables reachable through it, so the
       endpoint does not become a broad path to every table in the account.
    3. Add a `aws:SourceVpce` condition on the table's resource policy where access
       should be possible only from inside the VPC.
  "
  tag severity:              'medium'
  tag nist:                  ['SA-8']
  tag cci:                   ['CCI-000664']
  tag cis_number:            '4.5'
  tag cis_rid:               '4.5'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0405r1_rule'
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
    its('regions_without_dynamodb_endpoint') { should be_empty }
  end
end
