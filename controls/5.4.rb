# encoding: UTF-8

control 'C-5.4' do
  title 'Ensure Automatic Updates and Patching are Enabled'
  desc  "
    Enabling automatic updates and patching for Amazon ElastiCache ensures that your ElastiCache clusters run the latest software versions with important security fixes and enhancements.

    Automatic updates help the software be updated and address any vulnerabilities within the software that can help business with any potential exists that can impact the business and prevent any unauthorized access.
  "
  desc  'rationale', "
    Enabling automatic updates and patching for Amazon ElastiCache ensures that your ElastiCache clusters run the latest software versions with important security fixes and enhancements.

    Automatic updates help the software be updated and address any vulnerabilities within the software that can help business with any potential exists that can impact the business and prevent any unauthorized access.
  "
  desc  'check', "
    1. Sign in to the AWS Management Console
    - Sign in to the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the ElastiCache Console
    - Open the Amazon ElastiCache console by navigating to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/elasticache/.

    3. Select the ElastiCache Cluster
    - Choose the ElastiCache cluster you want to enable automatic updates and patching. 
    - Click on the cluster name to access its details page.

    4. Enable Automatic Updates
    - Click on the `Configuration` tab on the cluster details page.
    - Scroll down to the `Cluster details` section.
    - Under `Cluster maintenance and updates`, click `Modify`.
    - In the `Maintenance and updates` dialog, find the `Auto minor version upgrade` option and select `Enable`.
    - Leave other settings unchanged or adjust them according to your requirements.
    - Click `Save` to apply the changes.
 
    5. Verify Automatic Updates Status
    - Wait for a few moments for the changes to take effect.
    - Refresh the cluster details page to see the updated configuration.
    - Verify that the \"Auto minor version upgrade\" setting is now enabled for the ElastiCache cluster.
  "
  desc  'fix', "
        ```
        aws elasticache modify-replication-group --replication-group-id <group-id> --auto-minor-version-upgrade --preferred-maintenance-window <ddd:hh24:mi-ddd:hh24:mi> --apply-immediately
        ```

    1. Leave automatic minor version upgrades enabled so engine security fixes are
       picked up.
    2. Set a maintenance window in a low-traffic period and confirm the application
       reconnects cleanly after a node replacement.
    3. Engine major versions are not upgraded automatically. Track the running
       version against the deprecation schedule and plan the upgrade rather than
       being forced into it.
    4. Subscribe to ElastiCache events via SNS so required actions are seen.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '5.4'
  tag cis_rid:               '5.4'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0504r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('elasticache')
  impact 0.5
  scoped_items = scoped_or_na(aws_elasticache_clusters.ids,
                              in_scope: applicable_partition && applicable_service,
                              reason:   "ELASTICACHE out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')}) or none present in this account")

  scoped_items.each do |id|
    describe aws_elasticache_cluster(cache_cluster_id: id) do
      its('auto_minor_version_upgrade') { should eq true }
    end
  end
end
