# encoding: UTF-8

control 'C-2.11' do
  title 'Ensure Database has delete protection enabled'
  desc  "
    Ensure that delete protection is enabled on database instances to prevent accidental or unauthorized deletion. This setting safeguards critical databases by requiring explicit disabling of delete protection before deletion, reducing the risk of data loss through human error or malicious activity.

    Delete protection provides a safeguard against inadvertent or malicious deletion of critical databases. By requiring deliberate action to disable deletion protection, organizations mitigate risks associated with accidental data deletion and enhance the overall resilience of their data storage platform.
  "
  desc  'rationale', "
    Ensure that delete protection is enabled on database instances to prevent accidental or unauthorized deletion. This setting safeguards critical databases by requiring explicit disabling of delete protection before deletion, reducing the risk of data loss through human error or malicious activity.

    Delete protection provides a safeguard against inadvertent or malicious deletion of critical databases. By requiring deliberate action to disable deletion protection, organizations mitigate risks associated with accidental data deletion and enhance the overall resilience of their data storage platform.
  "
  desc  'check', "
    Run the following command to check if deletion protection is enabled on your Aurora DB cluster(s):

    ```
    aws rds describe-db-clusters \\
      --query \"DBClusters[*].{DBClusterIdentifier:DBClusterIdentifier,DeletionProtection:DeletionProtection}\" \\
      --output table
    ```

    - Review each cluster's DeletionProtection status.
    - Clusters marked as true have deletion protection enabled.
    - Identify any clusters with deletion protection disabled for remediation.
  "
  desc  'fix', "
    1. To enable deletion protection on an existing Aurora DB cluster:

    ```
    aws rds modify-db-cluster \\
      --db-cluster-identifier \\
      --deletion-protection \\
      --apply-immediately
    ```
    - Replace with your Aurora cluster ID.
    - This change is applied immediately without downtime.
    - Once enabled, the cluster cannot be deleted without first disabling deletion protection.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '2.11'
  tag cis_rid:               '2.11'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0211r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('rds')
  # Hoisted so an EMPTY collection is a declared state rather than an absent one.
  # The service can be in scope while the account holds none of the resource: the
  # loop below then never executed, the control registered no describe blocks, and
  # it emitted ZERO results — neither passed nor Not Applicable, just absent. A
  # control that asserts nothing while reporting not-red is the failure this
  # profile exists to catch, and it also fails `hdf convert`, whose schema requires
  # at least one result per requirement.
  scoped_items = aws_rds_clusters.entries
  applicable           = applicable_partition && applicable_service && !scoped_items.empty?

  impact 0.5
  impact 0.0 unless applicable

  only_if("RDS out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')}) or none present in this account") do
    applicable
  end

  allowed_engines = Array(input('rds_engines'))

  scoped_items.each do |c|
    next unless allowed_engines.empty? || allowed_engines.include?(c[:engine])

    describe aws_rds_cluster(db_cluster_identifier: c[:db_cluster_identifier]) do
      its('deletion_protection') { should eq true }
    end
  end
end
