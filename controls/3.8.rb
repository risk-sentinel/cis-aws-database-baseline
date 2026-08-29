# encoding: UTF-8

control 'C-3.8' do
  title 'Ensure to Regularly Patch Systems'
  desc  "
    Keep the database engine current by leaving automatic minor version upgrades
    enabled and planning major version upgrades before support ends.

    Minor versions carry the engine's security fixes. Disabling automatic upgrades
    defers them indefinitely, and the deferral is invisible - the instance keeps
    running and reports healthy while accumulating known vulnerabilities.
  "
  desc  'rationale', "
    Keep the database engine current by leaving automatic minor version upgrades
    enabled and planning major version upgrades before support ends.

    Minor versions carry the engine's security fixes. Disabling automatic upgrades
    defers them indefinitely, and the deferral is invisible - the instance keeps
    running and reports healthy while accumulating known vulnerabilities.
  "
  desc  'check', "
    1. Stay Informed about Database Engine Updates
    - Stay up-to-date with the latest information regarding database engine updates and patches provided by the respective database engine vendors (e.g., MySQL, PostgreSQL, Oracle, SQL Server).
    - Subscribe to release announcements, security bulletins, and updates from the database engine vendor or AWS.

    2. Review the Database Engine Documentation
    - Refer to the documentation provided by the database engine vendor to understand the recommended patching and update processes specific to the database engine you use on Amazon RDS.
    - Review the vendor's guidelines and best practices for applying updates and patches.

    3. Plan for Maintenance Windows
    - Determine regular maintenance windows during which you can schedule updates and patches for your RDS instances.
    - Coordinate with your team to ensure minimal disruption to your applications and users during the maintenance window.

    4. Enable Automated Minor Version Upgrades
    - In the Amazon RDS console, select the RDS instance you want to enable automated upgrades.
    - Under the `Maintenance & backups` or `Maintenance` section.
    - Enable the `Auto minor version upgrade` option.
    - This allows Amazon RDS to automatically apply eligible minor version upgrades to your RDS instances during the maintenance window.

    5. Monitor Available Updates
    - Regularly monitor the `Pending Maintenance` section in the Amazon RDS console for any updates or patches for your RDS instances.
    - Pay attention to notifications and alerts from AWS about pending updates.

    6. Schedule Updates and Patches
    - Review the available updates and patches and their associated release notes and security advisories.
    - Please select the appropriate updates based on their impact, criticality, and compatibility with your applications.
    - Schedule the updates and patches to be applied during the designated maintenance window.

    7. Apply Updates and Patches
    - During the scheduled maintenance window, Amazon RDS automatically applies the eligible updates and patches to your RDS instances.
    - Monitor the progress of the updates and patches through the Amazon RDS console.

    8. Test and Validate
    - After the updates and patches are applied, thoroughly test your applications to ensure they function as expected.
    - Validate the database performance, data integrity, and application functionality.

    9. Monitor for Issues
    - Monitor the performance and behavior of your RDS instances after the updates and patches are applied.
    - Keep an eye out for any issues or anomalies and address them promptly.

    10. Review and Document
    - Review the release notes and documentation of the applied updates and patches to understand the changes and improvements they bring.
    - Document the update and patching process, including the applied versions, dates, and any issues encountered.
  "
  desc  'fix', "
        ```
        aws rds modify-db-instance --db-instance-identifier <instance-id> --auto-minor-version-upgrade --preferred-maintenance-window <ddd:hh24:mi-ddd:hh24:mi> --apply-immediately
        ```

    1. Leave automatic minor version upgrades on. Minor versions carry the security
       fixes, and disabling this defers them indefinitely.
    2. Set a maintenance window in a low-traffic period, and confirm the application
       tolerates the brief failover a patch causes.
    3. Major version upgrades are not automatic. Track end of standard support for
       the running version and plan the upgrade before it arrives, rather than being
       moved to paid extended support by default.
    4. Review pending maintenance actions periodically:

        ```
        aws rds describe-pending-maintenance-actions
        ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '3.8'
  tag cis_rid:               '3.8'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0308r1_rule'
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

  # CIS 3.8 has both a technical bar (auto_minor_version_upgrade) and
  # an operational bar (patching cadence). We assert the technical bar
  # here; patching cadence is an attestation concern tracked outside
  # this profile.
  allowed_engines = Array(input('rds_engines'))

  aws_rds_instances.entries.each do |i|
    next unless allowed_engines.empty? || allowed_engines.include?(i[:engine])

    describe aws_rds_instance(db_instance_identifier: i[:db_instance_identifier]) do
      its('auto_minor_version_upgrade') { should eq true }
    end
  end
end
