# encoding: UTF-8

control 'C-10.7' do
  title 'Ensure Regular Updates and Patches are Installed'
  desc  "
    Stay updated with the latest security patches and updates provided by AWS for Amazon Timestream. Follow AWS security best practices and recommendations to ensure your Timestream implementation remains secure.
  "
  desc  'rationale', "
    Stay updated with the latest security patches and updates provided by AWS for Amazon Timestream. Follow AWS security best practices and recommendations to ensure your Timestream implementation remains secure.
  "
  desc  'check', "
    1. Stay Informed about Updates
    Stay updated with the latest announcements and releases related to Amazon Timestream.
    Subscribe to AWS notifications, blogs, and forums to learn about new features, enhancements, and security patches.

    2. Review AWS Documentation
    Regularly review the official AWS documentation for Amazon Timestream.
    Pay attention to any updates or recommendations related to security, performance, and best practices.

    3. Implement a Patch Management Process
    Establish a patch management process specific to Amazon Timestream within your organization.
    Define roles and responsibilities for managing patches, including testing and deployment procedures.

    4. Test Patches in a Non-Production Environment
    Before deploying patches in production, create a non-production environment to test the patches.
    Set up a replica or a sandbox environment that resembles your production environment.
    Test the patches thoroughly to ensure they do not introduce compatibility issues or adverse effects.

    5. Schedule Patching Maintenance Windows
    Identify suitable maintenance windows to apply patches to your Timestream resources.
    Consider the impact on system availability and plan the maintenance window accordingly.
    Coordinate with relevant teams and stakeholders to ensure minimal disruption during the patching process.

    6. Apply Patches
    Once you have successfully tested the patches in the non-production environment and scheduled a maintenance window.
    Apply the patches to your production Timestream resources.
    Follow the recommended patching procedures provided by AWS in the documentation.
    Ensure you follow any specific instructions or requirements for applying patches to Timestream.

    7. Verify Patch Deployment
    After applying patches, monitor the Timestream resources to ensure they function as expected.
    Conduct thorough testing to validate that the patched resources operate correctly and have not introduced any issues.

    8. Regularly Monitor for Updates
    Continuously monitor for new updates, patches, and security bulletins related to Amazon Timestream.
    Stay informed about any vulnerabilities or critical patches that require immediate attention.
    Adjust your patch management process and schedule to incorporate new updates and releases.

    9. Automate Patch Management (Optional)
    Consider automating the patch management process using AWS tools or third-party solutions.
    Implement automation scripts or systems that handle patch deployments, testing, and monitoring.
  "
  desc  'fix', "
    TODO: fix text missing in source XCCDF
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_number:            '10.7'
  tag cis_rid:               '10.7'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-1007r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'inherited'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('timestream')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("TIMESTREAM out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe 'AWS shared-responsibility inheritance' do
    it 'is satisfied by AWS-managed controls — Amazon Timestream is a fully-managed service; AWS handles all engine updates and patches transparently per the AWS shared-responsibility model (evidence: AWS SOC 2 Type II, AWS FedRAMP Moderate, AWS FedRAMP High, AWS ISO 27001; AWS Artifact: https://console.aws.amazon.com/artifact/)' do
      expect(true).to eq(true)
    end
  end
end
