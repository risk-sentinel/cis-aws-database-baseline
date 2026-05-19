# encoding: UTF-8

control 'C-3.1' do
  title 'Ensure to Choose the Appropriate Database Engine'
  desc  "
    TODO: description missing in source XCCDF
  "
  desc  'rationale', "
    TODO: description missing in source XCCDF
  "
  desc  'check', "
    1. Evaluate Your Requirements
    - Understand your application's specific requirements, such as performance, scalability, data volume, and compatibility with existing systems.
    - Consider factors like data structure, workload type (OLTP or OLAP), and specific features required by your application.

    2. Research Available Database Engines
    - Familiarize yourself with the available database engine options supported by Amazon RDS.
    - Research each database engine's capabilities, features, performance characteristics, and licensing models.

    3. Compare Features and Compatibility
    - Compare the features and capabilities of each database engine with your application's requirements.
    - Evaluate data types, indexing options, query optimization, high availability, replication, and backup and restore capabilities.
    - Consider compatibility with your existing applications, frameworks, and tools.

    4. Evaluate Performance and Scalability
    - Consider the performance characteristics of each database engine, including throughput, latency, and concurrency capabilities.
    - Evaluate scalability options, such as horizontal scaling or vertical scaling.
    - Analyze benchmarks, customer reviews, and case studies to gain insights into the performance of each database engine.

    5. Consider Managed Database Services
    - Assess the benefits of Amazon RDS managed database services, such as Amazon Aurora, which offers high performance, scalability, and built-in fault tolerance.
    - Evaluate the additional features and optimizations Amazon Aurora provides compared to traditional database engines.

    6. Evaluate Licensing and Costs
    - Consider the licensing models and costs associated with each database engine, including license fees and support costs.
    - Evaluate the pricing structure of the database engines in terms of instance types, storage, data transfer, and other factors.

    7. Determine Vendor Support
    - Evaluate the level of support the database engine vendors provide, including documentation, forums, community support, and enterprise support options.
    - Consider the vendor's reputation, track record, and commitment to security and compliance.

    8. Make an Informed Decision
    - Select the database engine that best aligns with your application requirements, performance needs, scalability goals, compatibility, and budget based on your evaluation and analysis.
    - Consider long-term considerations such as potential future growth, flexibility, and ease of migration to other database engines if needed.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['MA-3 a']
  tag cci:                   ['CCI-000865']
  tag cis_number:            '3.1'
  tag cis_rid:               '3.1'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0301r1_rule'
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

  describe aws_rds_cluster_compliance(
    regions:           input('scan_regions'),
    engines:           input('rds_engines'),
    approved_engines:  input('approved_db_engines'),
  ) do
    its('clusters_with_unapproved_engine') { should be_empty }
  end
end
