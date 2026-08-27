# encoding: UTF-8

control 'C-5.1' do
  title 'Ensure Secure Access to ElastiCache'
  desc  "
    Securing access to Amazon ElastiCache involves implementing appropriate authentication and authorization mechanisms.
  "
  desc  'rationale', "
    Securing access to Amazon ElastiCache involves implementing appropriate authentication and authorization mechanisms.
  "
  desc  'check', "
    1. Use AWS Identity and Access Management (IAM)
    - Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam/.
    - Create IAM users or roles for individuals or applications needing ElastiCache access.
    - Define fine-grained permissions using IAM policies to allow only necessary actions on ElastiCache resources.
    - Assign IAM policies to the IAM users or roles to grant access.

    2. Implement Secure Network Access
    - Place your ElastiCache cluster within a Virtual Private Cloud (VPC) to control network access.
    - Create and configure security groups to allow access only from trusted networks or specific IP ranges.
    - Ensure your VPC's network ACLs (Access Control Lists) are properly configured to restrict inbound and outbound traffic.

    3. Enable Encryption in Transit
    - Configure your ElastiCache cluster to use SSL/TLS encryption for client connections.
    - Use the `--transit-encryption-enabled` parameter when creating or modifying the cluster to enable encryption in transit.
    - Update your client applications to connect to the ElastiCache cluster using SSL/TLS.

    4. Protect ElastiCache Credentials
    - Avoid sharing access keys, secret keys, or IAM user credentials between individuals.
    - Use IAM roles for Amazon EC2 instances or other AWS services to securely access ElastiCache without needing credentials.
    - Rotate your access keys regularly and disable or remove unnecessary IAM users or roles.

    5. Enable Event Logging and Monitoring
    - Enable CloudWatch Logs for your ElastiCache clusters to capture logs and monitor activities.
    - Configure CloudWatch Alarms to be notified of any unusual or suspicious behavior.
    - Set up CloudTrail to log API calls made to ElastiCache for auditing and compliance purposes.

    6. Regularly Review and Update Access Controls
    - Perform regular reviews of IAM policies, security groups, and network ACLs to ensure they align with your security requirements.
    - Remove any unnecessary or excessive privileges from IAM policies.
    - Stay updated with AWS security best practices and recommendations to improve access controls.
  "
  desc  'fix', "
    1. Place the cluster in private subnets via a cache subnet group, with no route
       to an internet gateway.
    2. Restrict the cluster security group to the cache port from the application
       security group only:

        ```
        aws ec2 authorize-security-group-ingress --group-id <cache-sg-id> --protocol tcp --port 6379 --source-group <app-sg-id>
        ```

    3. Enable encryption in transit and Redis AUTH, or RBAC user groups, so network
       position alone does not grant access.
    4. Remove any rule permitting the cache port from a broad CIDR. An unauthenticated
       Redis reachable on the network is equivalent to published data.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '5.1'
  tag cis_rid:               '5.1'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0501r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag exec_validated:        false

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable_service   = Array(input('applicable_services')).empty? || Array(input('applicable_services')).include?('elasticache')
  applicable           = applicable_partition && applicable_service

  impact 0.5
  impact 0.0 unless applicable

  only_if("ELASTICACHE out of scope (partition=#{input('aws_partition')}, applicable_services=#{input('applicable_services')})") do
    applicable
  end

  describe aws_elasticache_compliance(regions: input('scan_regions')) do
    its('groups_without_secure_access') { should be_empty }
  end
end
