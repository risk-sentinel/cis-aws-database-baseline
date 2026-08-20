# encoding: UTF-8

control 'C-5.3' do
  title 'Ensure Encryption at Rest and in Transit is configured'
  desc  "
    Enabling encryption at rest and in transit for Amazon ElastiCache helps protect your data when it is stored and transmitted.

    Enabling encryption at rest secured the users data where it is stored. Enabling encryption in transit helps that the data is protected when it is moving from one location to another.
  "
  desc  'rationale', "
    Enabling encryption at rest and in transit for Amazon ElastiCache helps protect your data when it is stored and transmitted.

    Enabling encryption at rest secured the users data where it is stored. Enabling encryption in transit helps that the data is protected when it is moving from one location to another.
  "
  desc  'check', "
    1. Enable Encryption at Rest
    - Sign in to the AWS Management Console and open the Amazon ElastiCache console at https://console.aws.amazon.com/elasticache/.
    - Create a new ElastiCache cluster or select an existing cluster.
    - On the cluster details page, click the `Encryption` tab.
    - Select the option to enable encryption Under the `Encryption at Rest` section.
    - Choose the desired encryption type:
    	- list text hereDefault Encryption: Select this option to use the default AWS-managed key for encryption.
    	- list text hereCustomer Managed Key (CMK): Select this option to use your own AWS Key Management Service (KMS) customer-managed key for encryption.
    - If you selected `Customer Managed Key (CMK)`, choose the appropriate KMS key from the dropdown menu.
    - Click \"Save changes\" to enable encryption at rest for the ElastiCache cluster.

    2. Enable Encryption in Transit
    - On the ElastiCache cluster details page, click the `Encryption` tab.
    - Select the option to enable encryption Under the \"Encryption in Transit\" section.
    - Choose the desired encryption type:
    	- list text hereTransit encryption enabled with SSL/TLS: Select this option to enable encryption in transit using SSL/TLS encryption.
    	- list text hereTransit encryption disabled: Select this option if you do not require encryption in transit.
    - Click `Save changes` to enable encryption in transit for the ElastiCache cluster.

    3. Verify the Encryption Status
    - Wait a few minutes for the changes to propagate and the encryption to take effect.
    - Refresh the ElastiCache console and navigate to the cluster details page.
    - Verify that the encryption status is now enabled for both encryptions at rest and in transit.
  "
  desc  'fix', "
    The user has two options when it comes to encryption at rest and in transit to choose from. Depending on what actions the user selects from it determines how their data is going to be protected.
  "
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'SC-28', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-001199', 'CCI-000051']
  tag cis_number:            '5.3'
  tag cis_rid:               '5.3'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0503r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('elasticache')
  # Hoisted so an EMPTY collection is a declared state rather than an absent one.
  # The service can be in scope while the account holds none of the resource: the
  # loop below then never executed, the control registered no describe blocks, and
  # it emitted ZERO results — neither passed nor Not Applicable, just absent. A
  # control that asserts nothing while reporting not-red is the failure this
  # profile exists to catch, and it also fails `hdf convert`, whose schema requires
  # at least one result per requirement.
  scoped_items = aws_elasticache_clusters.ids
  applicable           = applicable_partition && applicable_service && !scoped_items.empty?

  impact 0.5
  impact 0.0 unless applicable

  only_if("ELASTICACHE out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')}) or none present in this account") do
    applicable
  end

  scoped_items.each do |id|
    describe aws_elasticache_cluster(cache_cluster_id: id) do
      it { should be_encrypted_at_rest }
      it { should be_encrypted_at_transit }
    end
  end
end
