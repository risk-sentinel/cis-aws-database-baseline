# encoding: UTF-8

control 'C-3.2' do
  title 'Ensure to Create The Appropriate Deployment Configuration'
  desc  "
    This control is important and helps businesses to choose from two deployment options, either single or multi-AZ deployment. Depending on the business factor and their security needs the organization is then encouraged to make a decision that would benefit them.
  "
  desc  'rationale', "
    This control is important and helps businesses to choose from two deployment options, either single or multi-AZ deployment. Depending on the business factor and their security needs the organization is then encouraged to make a decision that would benefit them.
  "
  desc  'check', "
    1. Evaluate High Availability Requirements
    - Assess the high availability needs of your application. Consider factors such as uptime requirements, business continuity, and disaster recovery.
    - Determine if your application requires automatic failover, data durability, and minimal downtime during maintenance or outages.

    2. Understand RDS Deployment Options
    - Familiarize yourself with the deployment options available on Amazon RDS. These include single-AZ (Availability Zone) and multi-AZ deployments.
    - Understand the differences between these options regarding availability, durability, and cost.

    3. Single-AZ Deployment
    - Consider a single-AZ deployment if high availability is not a critical requirement for your application.
    - In a single-AZ deployment, your database runs in a single Availability Zone, providing basic durability and availability.

    4. Multi-AZ Deployment
    - Choose a multi-AZ deployment if high availability and automatic failover are crucial for your application.
    - In a multi-AZ deployment, your database is replicated synchronously to a standby replica in a different Availability Zone, providing automatic failover in the event of a primary database failure.
    - Multi-AZ deployments provide enhanced availability and durability, ensuring minimal downtime during maintenance or outages.

    5. Evaluate Cost Implications
    - Consider the cost implications of your deployment choice.
    - Multi-AZ deployments incur additional costs than single-AZ deployments due to the replication and standby infrastructure.

    6. Make a Deployment Decision
    - Based on your evaluation of high availability requirements, consider the trade-offs between single-AZ and multi-AZ deployments.
    - Choose the appropriate deployment configuration that meets your application's availability, durability, and cost requirements.

    7. Configure RDS Deployment
    - Once you have determined the deployment configuration, go to the Amazon RDS console.
    - Create a new database instance or modify an existing one to match your chosen deployment configuration.
    - Follow the prompts and configure the deployment options, selecting the desired AZs and replication settings.
    - Adjust other configuration settings, such as instance type, storage, and backup options, based on your application's needs.

    8. Test and Monitor
    - After the deployment is set up, thoroughly test your application's functionality and performance.
    - Monitor the RDS instance and replication status using the Amazon RDS console or CloudWatch metrics.
    - Ensure that the database failover and automatic maintenance operations work as expected.
  "
  desc  'fix', "
    Deploy for the availability the workload actually requires.

        ```
        aws rds modify-db-instance --db-instance-identifier <instance-id> --multi-az --apply-immediately
        ```

    1. Enable Multi-AZ for anything production. A single-AZ instance loses the
       database for the duration of an AZ event.
    2. For Aurora, place at least one reader in a second Availability Zone and
       confirm the failover priority ordering is what you intend.
    3. Enable deletion protection so an accidental delete call cannot remove the
       cluster.
    4. Test failover rather than assuming it: `aws rds failover-db-cluster` during a
       maintenance window tells you the application reconnects.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '3.2'
  tag cis_rid:               '3.2'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0302r1_rule'
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

  describe aws_rds_cluster_compliance(regions: input('scan_regions'), engines: input('rds_engines')) do
    its('clusters_without_multi_az') { should be_empty }
  end
end
