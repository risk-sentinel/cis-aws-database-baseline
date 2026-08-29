# encoding: UTF-8

control 'C-9.3' do
  title 'Ensure Data in Transit is Encrypted'
  desc  "
    Enabling encryption in transit helps that the data is protected when it is moving from one location to another.
  "
  desc  'rationale', "
    Enabling encryption in transit helps that the data is protected when it is moving from one location to another.
  "
  desc  'check', "
    1. Sign into the AWS Management Console 
    - Sign into the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon Neptune Console 
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/neptune/.

    3. Select the Neptune Cluster 
    - Choose the Amazon Neptune cluster for which you want to implement encryption in transit.
    - Click on the cluster name to access its details page.

    4. Enable SSL/TLS Encryption
    - In the cluster details page, navigate to the `Configuration` or `Encryption in Transit` section.
    - Under `Encryption in Transit`, ensure that the `Enable` option is selected.
    - Optionally, you can also select the `Enforce` option to require SSL/TLS encryption for all client connections to the Neptune cluster.
    - Click `Apply Changes` to enable SSL/TLS encryption for the Neptune cluster.

    5. Update Client Applications
    - When connecting to the Neptune cluster, update your client applications to establish an SSL/TLS-encrypted connection.
    - Consult your client drivers or libraries documentation or configuration settings to enable SSL/TLS encryption.
    - Configure the necessary SSL/TLS settings, such as specifying the SSL/TLS certificate to use.

    6. Verify Encryption in Transit
    - Test the connection to the Neptune cluster from your client application.
    - Ensure that the connection is established using SSL/TLS encryption.
    - Verify that all data transmitted between your client applications and the Neptune cluster is encrypted in transit.
  "
  desc  'fix', "
    Require HTTPS at the cluster rather than relying on clients to choose it.

        ```
        aws neptune modify-db-cluster-parameter-group --db-cluster-parameter-group-name <pg-name> --parameters 'ParameterName=neptune_enforce_ssl,ParameterValue=1,ApplyMethod=pending-reboot'
        ```

    1. With `neptune_enforce_ssl` set, plaintext connections are refused, so the
       guarantee does not depend on client configuration.
    2. Reboot for the parameter to take effect, and confirm clients connect over
       `https://` and verify the certificate.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_number:            '9.3'
  tag cis_rid:               '9.3'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0903r1_rule'
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
    its('clusters_without_in_transit_encryption') { should be_empty }
  end
end
