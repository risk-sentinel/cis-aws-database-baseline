# encoding: UTF-8

control 'C-9.4' do
  title 'Ensure Authentication and Access Control is Enabled'
  desc  "
    This helps ensure that there are specific IAM roles and policies that are given the necessary information within a Neptune DB cluster to operate as needed.
  "
  desc  'rationale', "
    This helps ensure that there are specific IAM roles and policies that are given the necessary information within a Neptune DB cluster to operate as needed.
  "
  desc  'check', "
    1. Sign into the AWS Management Console 
    - Sign into the AWS Management Console at https://console.aws.amazon.com/ with your AWS account credentials.

    2. Open the Amazon Neptune Console 
    - Navigate to the service using the `Find Services` search bar or by directly accessing the console at https://console.aws.amazon.com/neptune/.

    3. Select the Neptune Cluster 
    - Choose the Amazon Neptune cluster on which you want to implement authentication and access control. 
    - Click on the cluster name to access its details page.

    4. Enable IAM Database Authentication
    - In the cluster details page, navigate to the `Configuration` or `Database Authentication` section.
    - Under `Database Authentication`, select the option to enable IAM database authentication.
    - Click `Apply Changes` to enable IAM database authentication for the Neptune cluster.

    5. Configure IAM Roles and Policies
    - Open the AWS Identity and Access Management (IAM) console by navigating to `IAM` in the AWS Management Console.
    - Create IAM roles and policies that define the desired access control for your Neptune resources.
    - Assign the necessary permissions to the IAM roles to allow specific actions on the Neptune cluster, such as read, write, or manage operations.
    - Associate the IAM roles with the appropriate users, groups, or AWS services that need access to the Neptune cluster.

    6. Test IAM Database Authentication
    - Update your client applications or tools to use IAM database authentication when connecting to the Neptune cluster.
    - Configure your applications to assume the necessary IAM roles before establishing a connection to Neptune.
    - Test the connection from your client application to the Neptune cluster to verify that IAM database authentication is working as expected.
    - Ensure that users or services are authenticated and authorized based on the IAM roles and policies defined.

    7. Regularly Review and Update IAM Roles and Policies
    - Periodically review your IAM roles and policies to ensure they align with your security requirements and access control needs.
    - Make necessary updates to IAM roles and policies to adapt to changes in user access requirements or organizational security policies.
    - Follow the principle of least privilege and ensure that users or services have only the necessary permissions to perform their required actions on the Neptune cluster.
  "
  desc  'fix', "
    1. Enable IAM database authentication so requests are signed with SigV4 and tied
       to an IAM principal:

        ```
        aws neptune modify-db-cluster --db-cluster-identifier <cluster-id> --enable-iam-database-authentication --apply-immediately
        ```

    2. Without it, anything that can reach port 8182 can query the graph - network
       position becomes the only control.
    3. Scope IAM policies to the cluster resource ARN and to the specific actions
       (`neptune-db:ReadDataViaQuery`, `neptune-db:WriteDataViaQuery`), separating
       read and write roles.
    4. Confirm clients sign requests; an unsigned request fails closed once IAM auth
       is on, so stage the change.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_number:            '9.4'
  tag cis_rid:               '9.4'
  tag cis_benchmark:         'CIS AWS Database Services Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0904r1_rule'
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
    its('clusters_without_iam_authentication') { should be_empty }
  end
end
