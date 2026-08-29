# encoding: UTF-8

control 'C-3.12' do
  title 'Ensure Database is not Publicly accessible'
  desc  "
    RDS databases must not be publicly accessible. This means the database's network configuration should prevent assignment of public IP addresses or exposure to the public internet, ensuring that connections are only permitted from trusted internal networks.

    Restricting public access to databases greatly reduces the attack surface for malicious actors. Publicly accessible databases are highly vulnerable to unauthorized login attempts, exploitation of software vulnerabilities and data breaches. Enforcing private access restricts connectivity and enforces the principle of least privilege and network segmentation.
  "
  desc  'rationale', "
    RDS databases must not be publicly accessible. This means the database's network configuration should prevent assignment of public IP addresses or exposure to the public internet, ensuring that connections are only permitted from trusted internal networks.

    Restricting public access to databases greatly reduces the attack surface for malicious actors. Publicly accessible databases are highly vulnerable to unauthorized login attempts, exploitation of software vulnerabilities and data breaches. Enforcing private access restricts connectivity and enforces the principle of least privilege and network segmentation.
  "
  desc  'check', "
    1. Sign in to the AWS Management Console where the RDS database cluster you are auditing resides.

    2. Navigate to the Amazon Aurora and RDS Dashboard.
    - You can find this under the Database category.

    3. Select the DB instance name you wish to audit.
    - This opens the details page for your specific RDS DB instance.

    4. Under the Connectivity & security tab, check the value of Publicly accessible:
    - If Set to No, the instance is not publicly accessible; no further network verification is needed.​
    - If Set to Yes, continue with additional steps to fully assess exposure.

    5. In the Networking section under Connectivity & security, locate the Subnets for the database:
    - Right-click on the subnet link and open it in a new tab for further inspection.

    6. With the subnet selected, review the attached Route Table:
    - Check for routes with Destination: 0.0.0.0/0 and Target: an Internet Gateway (ID starts with igw-).​
    - If such a route exists, it enables access to the database from the public internet.

    If the database is marked as \"Publicly accessible: Yes\" and the subnets contain a route to 0.0.0.0/0 via an Internet Gateway, the instance is exposed to the public internet.
  "
  desc  'fix', "
    1. List your RDS cluster's DB instances with:
    ```
    aws rds describe-db-instances --query \"DBInstances[?DBClusterIdentifier==' '].DBInstanceIdentifier\"
    ```
    - Replace with your actual RDS cluster identifier.

    2. For each DB instance, run the following command:
    ```
    aws rds modify-db-instance --db-instance-identifier --no-publicly-accessible --apply-immediately
    ```
    - Replace with the name of your DB instance. The --apply-immediately flag ensures the change is applied right away.​

    3. Verify changes - confirm that \"Publicly Accessible\" is now set to \"No\" for each DB instance:
    ```
    aws rds describe-db-instances --db-instance-identifier --query \"DBInstances[0].PubliclyAccessible\"
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SA-8']
  tag ksi:                   ['KSI-PIY-RSD']
  tag nist_r4:               ['SA-8']
  tag cci:                   ['CCI-000664']
  tag cis_number:            '3.12'
  tag cis_rid:               '3.12'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0312r1_rule'
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

  # Same technical bar as CIS 2.9 — redundant coverage by design.
  allowed_engines = Array(input('rds_engines'))

  aws_rds_instances.entries.each do |i|
    next unless allowed_engines.empty? || allowed_engines.include?(i[:engine])

    describe aws_rds_instance(db_instance_identifier: i[:db_instance_identifier]) do
      its('publicly_accessible') { should eq false }
    end
  end
end
