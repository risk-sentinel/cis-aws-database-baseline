# encoding: UTF-8

control 'C-3.6' do
  title 'Enable Encryption in Transit'
  desc  "
    Amazon Relational Database uses SSL/TLS to encrypt data during transit. To secure your data in transit the individual should identify their client application and what is supported by SSL/TLS to configure it correctly.
  "
  desc  'rationale', "
    Amazon Relational Database uses SSL/TLS to encrypt data during transit. To secure your data in transit the individual should identify their client application and what is supported by SSL/TLS to configure it correctly.
  "
  desc  'check', "
    1. Sign into the AWS Management Console 
    - Sign into the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon RDS Console 
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/rds/.

    3. Select the RDS Instance 
    - Choose the Amazon RDS instance you want to implement encryption in transit. 
    - Click on the instance name to access its details page.
    - In the instance details page, navigate to the `Configuration` or `Encryption & Security` section.

    4. Enable SSL/TLS
    - Under the `Connectivity` or `Encryption in Transit` section
    - Click the `Modify` or `Edit` option to enable SSL/TLS encryption.
    - Select the option to enable SSL/TLS encryption.
    - Choose the SSL/TLS certificate authority (CA) certificate option that best suits your needs:
    	- If you have an existing certificate, select `Use a certificate from ACM (AWS Certificate Manager)` or `Use a certificate from AWS Secrets Manager`.
    	- If you do not have a certificate, select `Generate a new certificate`.
    Click `Continue` or `Save` to apply the changes.

    5. Verify SSL/TLS Encryption
    - After enabling SSL/TLS encryption, monitor the encryption status of your RDS instance.
    - In the RDS console, check the `Connectivity` or \"Encryption in Transit\" section to ensure that SSL/TLS encryption is enabled, and the status is \"In Progress\" or \"Enabled.\"

    6. Test SSL/TLS Encryption
    - Connect to your RDS instance using a database client or application that supports SSL/TLS encryption.
    - Configure the client or application to use SSL/TLS encryption by specifying the SSL/TLS certificate details.
    - Verify that the connection is established successfully with SSL/TLS encryption.

    7. Monitor and Manage SSL/TLS Certificates
    - Regularly monitor the SSL/TLS certificates associated with your RDS instances.
    - Manage certificate expiration and renewal to ensure uninterrupted SSL/TLS encryption.
  "
  desc  'fix', "
    Require TLS at the engine, rather than trusting every client to opt in.

    1. In the parameter group, set the engine's enforcement parameter and reboot to
       apply: `rds.force_ssl=1` for PostgreSQL and SQL Server, `require_secure_transport=ON`
       for MySQL and MariaDB.

        ```
        aws rds modify-db-parameter-group --db-parameter-group-name <pg-name> --parameters 'ParameterName=rds.force_ssl,ParameterValue=1,ApplyMethod=pending-reboot'
        ```

    2. Distribute the RDS CA bundle and configure clients to verify the server
       certificate. Encryption without verification still permits interception.
    3. Confirm existing sessions are encrypted before enforcing, or unprepared
       clients will fail to connect at the reboot.
  "
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '3.6'
  tag cis_rid:               '3.6'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0306r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('rds')
  impact 0.5
  scoped_items = scoped_or_na(aws_rds_clusters.entries,
                              in_scope: applicable_partition && applicable_service,
                              reason:   "RDS out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')}) or none present in this account")

  # Same technical bar as CIS 2.3 — engine-level TLS enforcement via
  # cluster parameter group. Uses the local aws_rds_cluster_parameter_group
  # resource added in commit 577f1bd.
  allowed_engines = Array(input('rds_engines'))

  scoped_items.each do |cluster|
    next unless allowed_engines.empty? || allowed_engines.include?(cluster[:engine])

    param_group = cluster[:db_cluster_parameter_group]
    engine      = cluster[:engine]
    cluster_id  = cluster[:db_cluster_identifier]

    case engine
    when "aurora-postgresql", "postgres"
      describe "#{cluster_id} (engine #{engine}) — parameter group #{param_group} enforces TLS" do
        subject { aws_rds_cluster_parameter_group(name: param_group) }
        it { should exist }
        its("parameter_value('rds.force_ssl')") { should eq "1" }
      end
    when "aurora-mysql", "mysql", "mariadb"
      describe "#{cluster_id} (engine #{engine}) — parameter group #{param_group} enforces TLS" do
        subject { aws_rds_cluster_parameter_group(name: param_group) }
        it { should exist }
        its("require_secure_transport_enabled?") { should eq true }
      end
    else
      describe "#{cluster_id} (engine #{engine})" do
        skip "pending-resource: TLS-enforcement parameter name not yet mapped for engine '#{engine}'"
      end
    end
  end
end
