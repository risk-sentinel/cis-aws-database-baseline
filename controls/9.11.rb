# encoding: UTF-8

control 'C-9.11' do
  title 'Ensure Neptune DB instances are deployed across multiple Availability Zones (AZs)'
  desc  "
    Deploying Amazon Neptune across multiple Availability Zones means configuring the database cluster nodes (primary and replicas) to be distributed in different AZs within the same AWS region. This multi-AZ deployment improves fault tolerance and availability by mitigating risks associated with failure or degradation in a single Availability Zone. If the primary node or an AZ becomes unavailable, Neptune can automatically fail over to a replica in a different AZ, minimizing downtime and data unavailability.

    Distributing Neptune DBs across multiple AZs protects the database from localized infrastructure failures, such as power outages, networking disruptions, or hardware faults in a single AZ.
  "
  desc  'rationale', "
    Deploying Amazon Neptune across multiple Availability Zones means configuring the database cluster nodes (primary and replicas) to be distributed in different AZs within the same AWS region. This multi-AZ deployment improves fault tolerance and availability by mitigating risks associated with failure or degradation in a single Availability Zone. If the primary node or an AZ becomes unavailable, Neptune can automatically fail over to a replica in a different AZ, minimizing downtime and data unavailability.

    Distributing Neptune DBs across multiple AZs protects the database from localized infrastructure failures, such as power outages, networking disruptions, or hardware faults in a single AZ.
  "
  desc  'check', "
    List Multi-AZ status for all Neptune DB clusters

    ```
    aws neptune describe-db-clusters \\
      --query \"DBClusters[*].{DBClusterIdentifier:DBClusterIdentifier,Engine:Engine,MultiAZ:MultiAZ}\"
    ```
    - MultiAZ: true ⇒ Multi-AZ is enabled (compliant).
    - MultiAZ: false ⇒ Multi-AZ is not enabled (non-compliant).
  "
  desc  'fix', "
    Enable Multi-AZ on Neptune DB clusters by adding a reader replica in a different Availability Zone.

    1. Sign in to the AWS Management Console where the Aurora database cluster you are auditing resides.

    2. Navigate to the Neptune Dashboard.
    - You can find this under the Database category.

    3. Select the DB cluster where you want to create the reader instance.

    4. Choose Actions, and then choose Add reader.

    4. Configure the replica DB instance

    On the Create replica DB instance page, specify the following options:

    - DB instance class: Choose a DB instance class that matches or aligns with your primary instance (e.g., db.r5.large). This defines the processing and memory requirements for the Neptune replica.

    - Availability zone: Specify a different Availability Zone than the primary DB instance. This is critical for Multi-AZ deployment. The list shows only AZs that are mapped by the DB subnet group for the cluster.

    - Encryption: Enable or disable encryption (recommended: enable if primary has encryption enabled).

    - Read replica source: Choose the identifier of the primary instance to create the Neptune replica for.

    - DB instance identifier: Enter a unique name for the instance in your region. Consider including the AZ in the name (e.g., neptune-replica-us-east-1b).

    - Database port: Specify the port number on which the database accepts connections (default: 8182 for Neptune).

    - DB parameter group: Select the parameter group for this instance (typically the same as the primary).

    - Log exports: Choose any logs you want to publish (audit, slowquery, etc.).

    - Auto Minor Version Upgrade: Choose Yes to enable automatic minor version upgrades for the replica.

    5. Choose Create read replica to create the Neptune replica instance.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '9.11'
  tag cis_rid:               '9.11'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0911r1_rule'
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
    its('clusters_without_multi_az') { should be_empty }
  end
end
