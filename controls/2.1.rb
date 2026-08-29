# encoding: UTF-8

control 'C-2.1' do
  title 'Ensure the Use of Security Groups'
  desc  "
    Security groups act as a firewall for associated Amazon RDS DB instances, controlling both inbound and outbound traffic.

    Creating your severity group either inbound or outbound rules. Inbound rules allow an individual to create a rule that permits the traffic to go to a specific port depending on which source it's coming from. Outbound rules enable your instances to connect with one another allow them to connect to the internet.  If needed, you can limit the outgoing traffic.
  "
  desc  'rationale', "
    Security groups act as a firewall for associated Amazon RDS DB instances, controlling both inbound and outbound traffic.

    Creating your severity group either inbound or outbound rules. Inbound rules allow an individual to create a rule that permits the traffic to go to a specific port depending on which source it's coming from. Outbound rules enable your instances to connect with one another allow them to connect to the internet.  If needed, you can limit the outgoing traffic.
  "
  desc  'check', "
    1. Open the Amazon Console
    2. Go to Aurora and RDS (https://console.aws.amazon.com/rds/)
    3. Click on Databases
    4. For each database instance click the name of the instance and check that there is at least one VPC security group under Connectivity & security -> Security -> VPC security groups
  "
  desc  'fix', "
    Here is a step-by-step guide on how to create and use Security Groups for an Amazon Aurora instance:

    1. Sign in to AWS Management Console 
    If you do not already have an AWS account, you'll need to create one at https://aws.amazon.com.

    2. Navigate to Amazon EC2 Dashboard 
    Once you have logged in to the AWS Management Console, navigate to the EC2 service. You can find this under the `Compute` category.

    3. Create a New Security Group
    - In the EC2 Dashboard, find the `Network & Security` section on the left-side navigation pane, then click `Security Groups`. 
    - Click on the `Create Security Group` button.

    4. Configure the New Security Group
    - In the `Create Security Group` panel, give your new security group a name and a description. 
    - Select the VPC in which your Amazon Aurora instance will be deployed. 
    - Then click `Create`.

    5. Add Rules to the Security Group 
    After creating the Security Group, you can add inbound and outbound rules.
    For Inbound Rules: 
    - Click on the `Inbound rules` tab, then click `Edit inbound rules`.
    - Click `Add Rule`. For the type, select MYSQL/Aurora. For the source, you can specify the IP addresses allowed to access your Amazon Aurora instance.
    For Outbound Rules: 
    - Click on the `Outbound rules` tab, then click `Edit outbound rules`. Outbound rules allow your instances to communicate with other instances or access the internet. You can restrict outbound traffic if necessary. In most cases, you can leave the default setting, which allows all outbound traffic.

    6. Assign the Security Group to Amazon Aurora 
    - When launching a new Amazon Aurora instance (in the Amazon RDS dashboard), you can select your new security group in the `Configure advanced settings` step.
    - If your Aurora instance has already been launched, you can modify it to use the new security group by selecting the instance.
    - Click `Modify`, and then select the new security group.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '2.1'
  tag cis_rid:               '2.1'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0201r1_rule'
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

  allowed_engines = Array(input('rds_engines'))

  aws_rds_instances.entries.each do |i|
    next unless allowed_engines.empty? || allowed_engines.include?(i[:engine])

    describe aws_rds_instance(db_instance_identifier: i[:db_instance_identifier]) do
      its('vpc_security_groups') { should_not be_empty }
    end
  end
end
