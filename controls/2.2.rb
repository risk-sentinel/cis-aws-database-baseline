# encoding: UTF-8

control 'C-2.2' do
  title 'Ensure Data at Rest is Encrypted'
  desc  "
    Amazon Aurora allows you to encrypt your databases using keys you manage through AWS Key Management Service (KMS).

    Databases are likely to hold sensitive and critical data; therefore, it is highly
    recommended to implement encryption to protect your data from unauthorized access
    or disclosure.
  "
  desc  'rationale', "
    Amazon Aurora allows you to encrypt your databases using keys you manage through AWS Key Management Service (KMS).

    Databases are likely to hold sensitive and critical data; therefore, it is highly
    recommended to implement encryption to protect your data from unauthorized access
    or disclosure.
  "
  desc  'check', "
    1. Sign in to the AWS Management Console where the Aurora database cluster you are auditing resides.

    2. Navigate to the Amazon Aurora and RDS Dashboard:
    - You can find this under the Database category.

    3. Select the DB cluster name you wish to audit:
    - This opens the details page for your specific Aurora cluster.

    4. Check the encryption status under the Configuration section.
    - Confirm that the field Encryption is marked as Enabled.

    5. Verify KMS key usage (if your organization's standards require a customer-managed key):
    - In the Encryption section, identify the AWS KMS key associated with the cluster. Click the key link to open its details page. Confirm that it is a customer-managed KMS key, not an AWS-managed key.
    - Review additional key attributes to ensure compliance, including Key policy, Key rotation status, etc.
  "
  desc  'fix', "
    For existing Aurora databases:
    In order to encrypt an existing Aurora instance that was not initially created with encryption enabled, you will need to create a snapshot of the instance, make a copy of the snapshot with encryption enabled, and then restore the DB instance from the copied snapshot.

    For creating new Aurora databases with encryption at rest enabled: 
    1. Sign in to AWS Management Console 
    If you do not already have an AWS account, you'll need to create one at https://aws.amazon.com

    2. Navigate to the Amazon Aurora and RDS Dashboard:
    - You can find this under the Database category.

    3. Click on `Create Database` and choose Aurora as your engine option.

    4. In the `Additional Configuration` section, you will see an option labeled `Enable encryption`. Check this box to enable encryption for data at rest.
    - You will also need to select a master key to use for encryption. You can choose the default AWS managed key for RDS or a pre-created customer-managed AWS Key Management Service (KMS) that aligns with your organization's key management policies.

    5. Launch the DB Instance 
    - After you have selected the appropriate encryption settings, click `Create database`. 
    - Review your settings on the following page, and if everything looks correct, click `Launch DB Instance`.
  "
  tag severity:              'medium'
  tag nist:                  ['SC-28', 'AC-8 a']
  tag cci:                   ['CCI-001199', 'CCI-000051']
  tag cis_number:            '2.2'
  tag cis_rid:               '2.2'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0202r1_rule'
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

  allowed_engines = Array(input('rds_engines'))

  scoped_items.each do |c|
    next unless allowed_engines.empty? || allowed_engines.include?(c[:engine])

    describe aws_rds_cluster(db_cluster_identifier: c[:db_cluster_identifier]) do
      its('storage_encrypted') { should eq true }
    end
  end
end
