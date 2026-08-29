# encoding: UTF-8

control 'C-9.10' do
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
    List deletion protection status for all Neptune DB clusters

    ```
    aws neptune describe-db-clusters \\
      --query \"DBClusters[*].{DBClusterIdentifier:DBClusterIdentifier,Engine:Engine,DeletionProtection:DeletionProtection}\"
    ```
    - DeletionProtection: true ⇒ Deletion protection is enabled (compliant).
    - DeletionProtection: false ⇒ Deletion protection is not enabled (non-compliant).
  "
  desc  'fix', "
    Enable deletion protection on a specific Neptune cluster:

    ```
    aws neptune modify-db-cluster \\
      --db-cluster-identifier \\
      --deletion-protection \\
      --apply-immediately
    ```
    - --deletion-protection enables the deletion protection feature.
    - --apply-immediately applies the change without waiting for the next maintenance window.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '9.10'
  tag cis_rid:               '9.10'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0910r1_rule'
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
    its('clusters_without_deletion_protection') { should be_empty }
  end
end
