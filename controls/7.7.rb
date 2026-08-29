# encoding: UTF-8

control 'C-7.7' do
  title 'Ensure Regular Updates and Patches'
  desc  "
    Stay informed about the latest security updates and patches released by Amazon for DocumentDB. Regularly apply updates and patches to your DocumentDB instances to protect against known vulnerabilities.
  "
  desc  'rationale', "
    Stay informed about the latest security updates and patches released by Amazon for DocumentDB. Regularly apply updates and patches to your DocumentDB instances to protect against known vulnerabilities.
  "
  desc  'check', "
    1. Stay Informed
    - Stay updated with Amazon DocumentDB announcements, release notes, and security bulletins.
    - Subscribe to AWS newsletters, forums, and notifications to receive timely updates regarding updates and patches.

    2. Plan for Maintenance Windows
    - Determine a suitable maintenance window to apply updates and patches to your DocumentDB cluster.
    - Consider the impact on your applications and users when scheduling the maintenance window.

    3. Monitor the AWS Management Console
    - Regularly check the AWS Management Console for notifications related to available updates and patches for your DocumentDB cluster.
    - The console will provide information on new versions and available patches.

    4. Review the Release Notes and Changelog
    - Before applying any updates or patches, review the release notes and changelog for the new version or patch.
    - Pay attention to any compatibility or breaking changes that may require application adjustments.

    5. Create a Test Environment (Optional)
    - If feasible, create a separate test environment that closely resembles your production environment.
    - Deploy a copy of your DocumentDB cluster in the test environment to test the updates and patches before applying them to production.

    6. Apply Updates and Patches
    - During the scheduled maintenance window, initiate the process to apply updates and patches to your DocumentDB cluster.
    - Follow the recommended procedure provided by AWS, which may involve a few simple clicks in the AWS Management Console.
    - Ensure that you select the appropriate version or patch to apply.

    7. Monitor the Update Process
    - Monitor the progress of the update or patch application for your DocumentDB cluster.
    - AWS will provide status updates during the process to keep you informed.

    8. Verify Post-Update Functionality
    - After the update or patch is applied, test the functionality of your applications that rely on the DocumentDB cluster.
    - Verify that your applications are working as expected and that any integration or dependencies are intact.

    9. Review and Update Documentation
    - Update your documentation, including standard operating procedures (SOPs), to reflect the new version or patch applied to the DocumentDB cluster.
    - Document any changes or considerations specific to the update or patch.

    10. Monitor for New Updates
    - Continuously monitor for new updates and patches released by AWS for DocumentDB.
    - Repeat the update process regularly to ensure your DocumentDB cluster remains up to date with the latest security enhancements and bug fixes.
  "
  desc  'fix', "
        ```
        aws docdb modify-db-cluster --db-cluster-identifier <cluster-id> --preferred-maintenance-window <ddd:hh24:mi-ddd:hh24:mi> --apply-immediately
        ```

    1. Leave automatic minor version upgrades enabled on the instances so engine
       security fixes are applied.
    2. Set the maintenance window to a low-traffic period, and confirm the
       application reconnects after the failover a patch causes.
    3. Check pending maintenance actions periodically, and track the engine version
       against its support schedule so a major upgrade is planned rather than forced.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '7.7'
  tag cis_rid:               '7.7'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0707r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('documentdb')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("DOCUMENTDB out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe aws_rds_cluster_compliance(regions: input('scan_regions'), engines: ['docdb']) do
    its('clusters_without_auto_minor_upgrade') { should be_empty }
  end
end
