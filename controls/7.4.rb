# encoding: UTF-8

control 'C-7.4' do
  title 'Ensure Encryption in Transit is Enabled'
  desc  "
    Amazon Database DB uses SSL/TLS to encrypt data during transit. To secure your data in transit the individual should identify their client application and what is supported by TLS to configure it correctly.
  "
  desc  'rationale', "
    Amazon Database DB uses SSL/TLS to encrypt data during transit. To secure your data in transit the individual should identify their client application and what is supported by TLS to configure it correctly.
  "
  desc  'check', "
    1. Sign into the AWS Management Console
    - Sign into the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon DocumentDB Console
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/docdb/.

    3. Select the DocumentDB Cluster
    - Choose the Amazon DocumentDB cluster for which you want to enable encryption in transit.
    - Click on the cluster name to access its details page.
    - In the cluster details page, navigate to the \"Configuration\" section.

    4. Enable Encryption in Transit
    - Under the `Network & Security` section.
    - Click on the `Edit` button or `Modify` option to configure the encryption settings.
    - Enable the option for encryption in transit by choosing the appropriate setting.
    - Note that encryption in transit uses SSL/TLS to secure communications between your applications and the DocumentDB cluster.

    5. Save the Configuration
    - Click on the \"Save\" button to apply the encryption in transit configuration.
    - DocumentDB will automatically handle the SSL/TLS encryption for network traffic between clients and the cluster.

    6. Validate Encryption in Transit
    - Test the connectivity to your DocumentDB cluster from your applications or clients.
    - Ensure that the communication is established securely using SSL/TLS encryption.

    7. Monitor and Maintain Encryption in Transit
    - Regularly monitor the encryption in transit configuration for your DocumentDB cluster.
    - Stay informed about updates or changes in SSL/TLS protocols and encryption standards.
    - Keep your client applications current to ensure they support the latest encryption protocols.
  "
  desc  'fix', "
    DocumentDB enables TLS by default through the `tls` cluster parameter. Keep it
    on and verify clients honour it.

        ```
        aws docdb modify-db-cluster-parameter-group --db-cluster-parameter-group-name <pg-name> --parameters 'ParameterName=tls,ParameterValue=enabled,ApplyMethod=pending-reboot'
        ```

    1. Disabling `tls` is a deliberate act and should be treated as a finding.
    2. Distribute the Amazon RDS CA bundle and configure drivers to verify the
       server certificate, rather than passing an option that skips validation.
    3. Confirm no connection string in the application carries `tlsAllowInvalidCertificates`.
  "
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '7.4'
  tag cis_rid:               '7.4'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0704r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('documentdb')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("DOCUMENTDB out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe aws_rds_cluster_compliance(regions: input('scan_regions'), engines: ['docdb']) do
    its('clusters_without_in_transit_encryption') { should be_empty }
  end
end
