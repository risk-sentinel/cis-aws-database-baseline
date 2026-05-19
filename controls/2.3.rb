# encoding: UTF-8

control 'C-2.3' do
  title 'Ensure Data in Transit Encryption is Enforced'
  desc  "
    Use TLS (Transport Layer Security) to secure data in transit. Aurora supports TLS-encrypted connections between your application and your DB instance, and this configuration can be enforced so non-TLS connections are prohibited.

    Encrypting data in transit protects sensitive information from interception and tampering by unauthorized parties. Aurora supports TLS for securing client connections, however it is essential to ensure that client applications are properly configured to use TLS and that the database enforces encrypted connections.
  "
  desc  'rationale', "
    Use TLS (Transport Layer Security) to secure data in transit. Aurora supports TLS-encrypted connections between your application and your DB instance, and this configuration can be enforced so non-TLS connections are prohibited.

    Encrypting data in transit protects sensitive information from interception and tampering by unauthorized parties. Aurora supports TLS for securing client connections, however it is essential to ensure that client applications are properly configured to use TLS and that the database enforces encrypted connections.
  "
  desc  'check', "
    1. Sign in to the AWS Management Console where the Aurora database cluster you are auditing resides.

    2. Navigate to the Amazon Aurora and RDS Dashboard:
    - You can find this under the Database category.

    3. Select the DB cluster name you wish to audit:
    - This opens the details page for your specific Aurora cluster.

    4. Under Configuration, locate the DB cluster parameter group attached to this cluster:
    - Click on the parameter group name to review its parameters.

    5. Verify the following engine-specific parameters to confirm encryption in transit is enforced:
    - 5a. PostgreSQL: Confirm that rds.force_ssl = 1

    - 5b. MySQL: Confirm that require_secure_transport = ON (Only applicable for Aurora MySQL versions 2 and 3)

    Notes:

    - Make sure the parameter changes are applied and the cluster has been rebooted if necessary for the parameters to take effect.
  "
  desc  'fix', "
    1. Sign in to the AWS Management Console where the Aurora database cluster you are remediating resides.

    2. Navigate to the Amazon Aurora and RDS Dashboard:
    - You can find this under the Database category.

    3. Select the DB cluster name you wish to remediate:
    - This opens the details page for your specific Aurora cluster.

    4. Under Configuration, locate the DB cluster parameter group attached to this cluster:
    - Click on the parameter group name to remediate its parameters.

    5. Update the following engine-specific parameters to enforce encryption in transit at the database level:
    - PostgreSQL: Set rds.force_ssl = 1
    - MySQL: Set require_secure_transport = ON (applicable to Aurora MySQL versions 2 and 3 only).

    6. Reboot the database cluster to apply the parameter changes.

    7. Configure your client application for SSL/TLS connections:

    - Download the appropriate AWS-provided SSL/TLS certificates:
    For MySQL-compatible Aurora, Amazon provides an SSL certificate that you can download from their documentation.
    PostgreSQL-compatible Aurora uses the default PostgreSQL SSL certificate.

    - Once you have the appropriate certificate, you must configure your client application to use SSL/TLS. For example, in MySQL, you might use a command like this:

    ```
    mysql -h --ssl-ca= --ssl-mode=VERIFY_IDENTITY
    ```
    For PostgreSQL, you might use a command like this:

    ```
    psql \"host= sslmode=verify-ca sslrootcert= \"
    ```

    Replace with the endpoint for your DB instance, and replace with the path to the SSL certificate on your local machine.

    8. Verify Encryption After configuring your client to use SSL/TLS, you should verify that encryption in transit is working correctly. You can do this by checking the status of the SSL connection from within the database itself. For example, in MySQL, you can run the following command:

    ```
    SHOW STATUS LIKE 'Ssl_cipher';

    ```
    In PostgreSQL, you can run the following command:

    ```
    SHOW ssl;

    ```
    In both cases, if SSL is enabled, you should see a non-empty cipher suite or on as a result.
  "
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '2.3'
  tag cis_rid:               '2.3'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0203r1_rule'
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

  # Check that each cluster's parameter group enforces TLS at the
  # engine level. Engine-specific parameter: Postgres uses rds.force_ssl,
  # MySQL/MariaDB use require_secure_transport.
  allowed_engines = Array(input('rds_engines'))

  aws_rds_clusters.entries.each do |cluster|
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
      # Engines we don't have a specific parameter check for (Oracle,
      # SQL Server, etc.). Explicit skip so auditors see a deliberate
      # gap rather than silent no-coverage.
      describe "#{cluster_id} (engine #{engine})" do
        skip "pending-resource: TLS-enforcement parameter name not yet mapped for engine '#{engine}'"
      end
    end
  end
end
