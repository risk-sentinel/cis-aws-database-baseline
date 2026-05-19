# encoding: UTF-8

control 'C-8.4' do
  title 'Ensure Amazon Keyspaces tables have Point-in-Time Recovery (PITR) enabled'
  desc  "
    Ensure that Amazon Keyspaces tables have Point-in-Time Recovery (PITR) enabled. When PITR is enabled, Amazon Keyspaces automatically creates continuous backups of table data, allowing tables to be restored to any point in time within the last 35 days. This protection is applied at the table level and provides defense against accidental writes, deletions, and other data loss scenarios.

    Enabling PITR on Amazon Keyspaces tables provides continuous, automatic backup protection without requiring manual snapshot management or impacting table performance or availability. In the event of accidental data corruption, malicious writes, or system failures, PITR allows rapid recovery to any second within the last 35 days, significantly reducing data loss exposure and recovery time.
  "
  desc  'rationale', "
    Ensure that Amazon Keyspaces tables have Point-in-Time Recovery (PITR) enabled. When PITR is enabled, Amazon Keyspaces automatically creates continuous backups of table data, allowing tables to be restored to any point in time within the last 35 days. This protection is applied at the table level and provides defense against accidental writes, deletions, and other data loss scenarios.

    Enabling PITR on Amazon Keyspaces tables provides continuous, automatic backup protection without requiring manual snapshot management or impacting table performance or availability. In the event of accidental data corruption, malicious writes, or system failures, PITR allows rapid recovery to any second within the last 35 days, significantly reducing data loss exposure and recovery time.
  "
  desc  'check', "
    List PITR status for all tables in a keyspace:

    ```
    aws keyspaces get-table \\
      --keyspace-name \\
      --table-name ```

    - If the value of pointInTimeRecovery = DISABLED, this means PITR is turned off
  "
  desc  'fix', "
    Enable PITR on a specific table:

    ```
    aws keyspaces update-table \\
      --keyspace-name \\
      --table-name \\
      --point-in-time-recovery status=ENABLED 
    ```
    - This command enables PITR on the specified table in the keyspace.​
    - The change takes effect immediately with no performance impact.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '8.4'
  tag cis_rid:               '8.4'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0804r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('keyspaces')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("KEYSPACES out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  inv = aws_keyspaces_compliance(regions: input('scan_regions'))
  if inv.connection_error
    describe 'Amazon Keyspaces inventory' do
      skip "Requires manual review and attestation provided for this control (#{inv.connection_error})"
    end
  else
    describe inv do
      its('tables_without_pitr') { should be_empty }
    end
  end
end
