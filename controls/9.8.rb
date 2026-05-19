# encoding: UTF-8

control 'C-9.8' do
  title 'Ensure Neptune Database is not Publicly accessible'
  desc  "
    Neptune databases must not be publicly accessible. This means the database's network configuration should prevent assignment of public IP addresses or exposure to the public internet, ensuring that connections are only permitted from trusted internal networks.

    Restricting public access to databases greatly reduces the attack surface for malicious actors. Publicly accessible databases are highly vulnerable to unauthorized login attempts, exploitation of software vulnerabilities and data breaches. Enforcing private access restricts connectivity and enforces the principle of least privilege and network segmentation.
  "
  desc  'rationale', "
    Neptune databases must not be publicly accessible. This means the database's network configuration should prevent assignment of public IP addresses or exposure to the public internet, ensuring that connections are only permitted from trusted internal networks.

    Restricting public access to databases greatly reduces the attack surface for malicious actors. Publicly accessible databases are highly vulnerable to unauthorized login attempts, exploitation of software vulnerabilities and data breaches. Enforcing private access restricts connectivity and enforces the principle of least privilege and network segmentation.
  "
  desc  'check', "
    1. Sign in to the AWS Management Console where the Aurora database cluster you are auditing resides.

    2. Navigate to the Neptune Dashboard.
    - You can find this under the Database category.

    3. Select the DB instance name you wish to audit.
    - This opens the details page for your specific Neptune DB instance.

    4. Under the Connectivity & Security tab, check the value of Publicly accessible:
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
    1. Disable public accessibility on a specific Neptune instance:

    ```
    aws neptune modify-db-instance \\
      --db-instance-identifier \\
      --no-publicly-accessible \\
      --apply-immediately
    ```
    - --no-publicly-accessible disables public accessibility for the instance.
    - --apply-immediately applies the change without waiting for the next maintenance window.

    2. Verify that public accessibility has been disabled

    ```
    aws neptune describe-db-instances \\
      --db-instance-identifier \\
      --query \"DBInstances[0].{DBInstanceIdentifier:DBInstanceIdentifier,PubliclyAccessible:PubliclyAccessible}\"
    ```

    - Confirm PubliclyAccessible is now false.
  "
  tag severity:              'medium'
  tag nist:                  ['SA-8']
  tag cci:                   ['CCI-000664']
  tag cis_number:            '9.8'
  tag cis_rid:               '9.8'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0908r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('neptune')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("NEPTUNE out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe aws_rds_cluster_compliance(regions: input('scan_regions'), engines: ['neptune']) do
    its('clusters_with_open_security_groups') { should be_empty }
  end
end
