package com.eucalyptus.tests.awssdk

import com.amazonaws.AmazonServiceException
import com.amazonaws.auth.AWSCredentials
import com.amazonaws.auth.AWSCredentialsProvider
import com.amazonaws.auth.BasicSessionCredentials
import com.amazonaws.internal.StaticCredentialsProvider
import com.amazonaws.services.ec2.AmazonEC2
import com.amazonaws.services.ec2.AmazonEC2Client
import com.amazonaws.services.ec2.model.DescribeImagesRequest
import com.amazonaws.services.ec2.model.DescribeSecurityGroupsRequest
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement
import com.amazonaws.services.identitymanagement.model.*
import com.amazonaws.services.securitytoken.AWSSecurityTokenService
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest
import org.testng.annotations.AfterClass
import org.testng.annotations.Test

import static com.eucalyptus.tests.awssdk.N4j.*

/**
 * Tests policy enforcement for IAM managed policies.
 *
 * Related issues:
 *   https://eucalyptus.atlassian.net/browse/EUCA-10773
 *
 * Related AWS doc:
 *   http://docs.aws.amazon.com/IAM/latest/UserGuide/policies-managed-vs-inline.html
 */
class TestIAMManagedPolicyPermissions {

  private final AWSCredentialsProvider testAcctAdminCredentials
  private final String testAcct
  private final AWSCredentialsProvider testAcctUserCredentials
  private final String testUser

  TestIAMManagedPolicyPermissions( ) {
    getCloudInfo( )
    this.testAcct = "${NAME_PREFIX}man-pol-per-test-acct"
    this.testUser = "${NAME_PREFIX}user"
    createAccount(testAcct)
    this.testAcctAdminCredentials = new StaticCredentialsProvider( getUserCreds(testAcct, 'admin') )
    createUser(testAcct, testUser)
    this.testAcctUserCredentials = new StaticCredentialsProvider( getUserCreds(testAcct, testUser) )
  }

  @AfterClass
  void tearDownAfterClass( ) {
    deleteAccount( testAcct )
  }

  private AmazonIdentityManagement getIamClient(
      AWSCredentialsProvider credentialsProvider = testAcctAdminCredentials
  ) {
    AWSCredentials creds = credentialsProvider.getCredentials( )
    getYouAreClient( creds.AWSAccessKeyId, creds.AWSSecretKey, IAM_ENDPOINT )
  }

  private AWSSecurityTokenService getStsClient(final AWSCredentialsProvider credentialsProvider) {
    AWSSecurityTokenServiceClient sts = new AWSSecurityTokenServiceClient(credentialsProvider)
    sts.setEndpoint(TOKENS_ENDPOINT)
    sts
  }

  private AmazonEC2 getEc2Client(
      AWSCredentialsProvider credentialsProvider = testAcctAdminCredentials
  ) {
    AmazonEC2 ec2 = new AmazonEC2Client(credentialsProvider)
    ec2.setEndpoint(EC2_ENDPOINT)
    ec2
  }

  @Test
  void iamManagedPolicyTest( ) {
    testInfo( this.getClass( ).getSimpleName( ) )

    final List<Runnable> cleanupTasks = [] as List<Runnable>
    try {
      getIamClient( ).with {  iam ->
        String secGroupPolicyName = "${NAME_PREFIX}-sec-group-policy"
        print( "Creating managed policy ${secGroupPolicyName}" )
        String secGroupPolicyArn = createPolicy( new CreatePolicyRequest(
            policyName: secGroupPolicyName,
            path: '/',
            description: "Policy management test policy ${secGroupPolicyName}",
            policyDocument: '''\
            {
              "Version": "2012-10-17",
              "Statement":[
                  {
                    "Effect": "Allow",
                    "Action": "ec2:DescribeSecurityGroups",
                    "Resource": "*"
                  }
              ]
            }
            '''.stripIndent( )
        ) ).with {
          assertThat( policy != null, "Expected policy" )
          print( "Created policy with details ${policy}" )
          policy.with {
            assertThat( arn != null, "Expected policy arn")
            arn
          }
        }
        print( "Created managed policy with arn ${secGroupPolicyArn}" )

        String imagePolicyName = "${NAME_PREFIX}-image-policy"
        print( "Creating managed policy ${imagePolicyName}" )
        String imagePolicyArn = createPolicy( new CreatePolicyRequest(
            policyName: imagePolicyName,
            path: '/',
            description: "Policy management test policy ${imagePolicyName}",
            policyDocument: '''\
            {
              "Version": "2012-10-17",
              "Statement":[
                  {
                    "Effect": "Allow",
                    "Action": "ec2:DescribeImages",
                    "Resource": "*"
                  }
              ]
            }
            '''.stripIndent( )
        ) ).with {
          assertThat( policy != null, "Expected policy" )
          print( "Created policy with details ${policy}" )
          policy.with {
            assertThat( arn != null, "Expected policy arn")
            arn
          }
        }
        print( "Created managed policy with arn ${imagePolicyArn}" )

        String groupName = "${NAME_PREFIX}group"
        String roleName = "${NAME_PREFIX}role"
        print( "Creating group for policy attachment testing ${groupName}" )
        createGroup( new CreateGroupRequest(
            groupName: groupName
        ))
        print( "Adding user ${testUser} to group ${groupName}" )
        addUserToGroup( new AddUserToGroupRequest(
            userName: testUser,
            groupName: groupName
        ) )
        print( "Creating role for policy attachment testing ${roleName}" )
        String roleArn = createRole( new CreateRoleRequest(
            roleName: roleName,
            assumeRolePolicyDocument: '''\
            {"Statement":[{"Effect":"Allow","Principal":{"Service":["ec2.amazonaws.com"]},"Action":["sts:AssumeRole"]}]}
            '''.stripIndent()
        )).with {
          role?.arn
        }

        print( "Attaching policy ${imagePolicyArn} to group ${groupName}" )
        attachGroupPolicy( new AttachGroupPolicyRequest(
            groupName: groupName,
            policyArn: imagePolicyArn
        ) )

        print( "Attaching policy ${secGroupPolicyArn} to role ${roleName}" )
        attachRolePolicy( new AttachRolePolicyRequest(
            roleName: roleName,
            policyArn: secGroupPolicyArn
        ) )

        print( "Attaching policy ${secGroupPolicyArn} to user ${testUser}" )
        attachUserPolicy( new AttachUserPolicyRequest(
            userName: testUser,
            policyArn: secGroupPolicyArn
        ) )

        print( "Sleeping 5 seconds so policies are applied" )
        sleep( 5 )

        // test user/group attached policy
        getEc2Client( testAcctUserCredentials ).with {
          print( "Describing groups with test account user credentials to test user attached policy" )
          describeSecurityGroups( new DescribeSecurityGroupsRequest( ) ).with {
            print( "Got security groups: ${securityGroups}" )
            assertThat( !securityGroups.isEmpty( ), 'Expected security groups' )
          }

          print( "Describing images with test account user credentials to test group attached policy" )
          describeImages( new DescribeImagesRequest( ) ).with {
            print( "Got images: ${images}" )
            assertThat( !images.isEmpty( ), 'Expected images' )
          }
        }

        // test creating new policy version without setting default does not change permissions
        print( "Creating new version for managed policy ${secGroupPolicyName}" )
        createPolicyVersion( new CreatePolicyVersionRequest(
            policyArn: secGroupPolicyArn,
            policyDocument: '''\
            {
              "Version": "2012-10-17",
              "Statement":[
                  {
                    "Effect": "Allow",
                    "Action": "ec2:Nothing",
                    "Resource": "*"
                  }
              ]
            }
            '''.stripIndent( )
        ) ).with {
          cleanupTasks.add{
            print( "Deleting version ${policyVersion.versionId} for managed policy ${secGroupPolicyName}" )
            deletePolicyVersion( new DeletePolicyVersionRequest(
                policyArn: secGroupPolicyArn,
                versionId: policyVersion.versionId
            ) )
          }
        }
        print( "Sleeping 5 seconds so policies are applied" )
        sleep( 5 )
        getEc2Client( testAcctUserCredentials ).with {
          print( "Describing groups with test account user credentials to test user attached policy" )
          describeSecurityGroups( new DescribeSecurityGroupsRequest( ) ).with {
            print( "Got security groups: ${securityGroups}" )
            assertThat( !securityGroups.isEmpty( ), 'Expected security groups' )
          }
        }

        // test creating new default policy version changes permissions
        print( "Creating new default version for managed policy ${secGroupPolicyName}" )
        createPolicyVersion( new CreatePolicyVersionRequest(
            policyArn: secGroupPolicyArn,
            policyDocument: '''\
            {
              "Version": "2012-10-17",
              "Statement":[
                  {
                    "Effect": "Allow",
                    "Action": "ec2:Nothing",
                    "Resource": "*"
                  }
              ]
            }
            '''.stripIndent( ),
            setAsDefault: true, // default version so will be enforced
        ) ).with {
          cleanupTasks.add{
            print( "Deleting version ${policyVersion.versionId} for managed policy ${secGroupPolicyName}" )
            deletePolicyVersion( new DeletePolicyVersionRequest(
                policyArn: secGroupPolicyArn,
                versionId: policyVersion.versionId
            ) )
          }
        }
        print( "Sleeping 5 seconds so policies are applied" )
        sleep( 5 )
        getEc2Client( testAcctUserCredentials ).with {
          print( "Describing groups with test account user credentials to test user attached policy" )
          try {
            describeSecurityGroups( new DescribeSecurityGroupsRequest( ) ).with {
              print( "Got security groups: ${securityGroups}" )
              assertThat( securityGroups.isEmpty( ), 'Expected no security groups' )
            }
          } catch (AmazonServiceException e) {
              print( "Describe security groups error when not permitted: ${e}" )
              assertThat(e.statusCode == 403, "Expected status code 403, but was: ${e.statusCode}")
          }
          void
        }

        // test switching back to original version restores original permissions
        print( "Switching to original policy version for managed policy ${secGroupPolicyName}" )
        setDefaultPolicyVersion( new SetDefaultPolicyVersionRequest(
            policyArn: secGroupPolicyArn,
            versionId: 'v1'
        ) )
        print( "Sleeping 5 seconds so policies are applied" )
        sleep( 5 )
        getEc2Client( testAcctUserCredentials ).with {
          print( "Describing groups with test account user credentials to test user attached policy" )
          describeSecurityGroups( new DescribeSecurityGroupsRequest( ) ).with {
            print( "Got security groups: ${securityGroups}" )
            assertThat( !securityGroups.isEmpty( ), 'Expected security groups' )
          }
        }

        // test role attached policy
        final AWSCredentialsProvider roleCredentialsProvider = new AWSCredentialsProvider() {
          AWSCredentials awsCredentials = null
          @Override
          public AWSCredentials getCredentials( ) {
            if ( awsCredentials == null ) {
              N4j.print "Getting credentials using assume role"
              awsCredentials = getStsClient( testAcctAdminCredentials ).with {
                assumeRole( new AssumeRoleRequest(
                    roleArn: roleArn,
                    roleSessionName: 'session-name-here'
                ) ).with {
                  assertThat(credentials != null, "Expected credentials")
                  assertThat(credentials.accessKeyId != null, "Expected credentials access key")
                  assertThat(credentials.secretAccessKey != null, "Expected credentials secret key")
                  assertThat(credentials.sessionToken != null, "Expected credentials session token")
                  new BasicSessionCredentials(
                      credentials.accessKeyId,
                      credentials.secretAccessKey,
                      credentials.sessionToken
                  )
                }
              }
            }
            awsCredentials
          }

          @Override
          public void refresh( ) {
            awsCredentials = null
          }
        }
        getEc2Client( roleCredentialsProvider ).with {
          print( "Describing groups with role to test role attached policy" )
          describeSecurityGroups( new DescribeSecurityGroupsRequest( ) ).with {
            print( "Got security groups: ${securityGroups}" )
            assertThat( !securityGroups.isEmpty( ), 'Expected security groups' )
          }
        }
      }

      print( 'Test complete' )
    } finally {
      // Attempt to clean up anything we created
      cleanupTasks.reverseEach { Runnable cleanupTask ->
        try {
          cleanupTask.run()
        } catch ( NoSuchEntityException e ) {
          print( 'Entity not found during cleanup.' )
        } catch ( AmazonServiceException e ) {
          print( "Service error during cleanup; code: ${e.errorCode}, message: ${e.message}" )
        } catch ( Exception e ) {
          e.printStackTrace()
        }
      }
    }
  }

  @Test
  void iamManagedPolicyArnConditionKeyTest( ) {
    testInfo( "${getClass( ).simpleName}PolicyArnConditionKey" )

    final List<Runnable> cleanupTasks = [] as List<Runnable>
    try {
      getIamClient( ).with { iam ->
        String policyName = "${NAME_PREFIX}-policy-arn-test"
        print( "Creating managed policy ${policyName}" )
        String policyArn = createPolicy( new CreatePolicyRequest(
            policyName: policyName,
            path: '/',
            description: "Policy arn condition key test policy ${policyName}",
            policyDocument: '''\
            {
              "Version": "2012-10-17",
              "Statement":[
                  {
                    "Effect": "Allow",
                    "Action": "ec2:Describe*",
                    "Resource": "*"
                  }
              ]
            }
            '''.stripIndent( )
        ) ).with {
          assertThat( policy != null, "Expected policy" )
          print( "Created policy with details ${policy}" )
          policy.with {
            assertThat( arn != null, "Expected policy arn")
            arn
          }
        }
        print( "Created managed policy with arn ${policyArn}" )

        String policyName2 = "${NAME_PREFIX}-policy-arn-test-2"
        print( "Creating managed policy ${policyName}" )
        String policyArn2 = createPolicy( new CreatePolicyRequest(
            policyName: policyName2,
            path: '/',
            description: "Policy arn condition key test policy ${policyName2}",
            policyDocument: '''\
            {
              "Version": "2012-10-17",
              "Statement":[
                  {
                    "Effect": "Allow",
                    "Action": "ec2:Describe*",
                    "Resource": "*"
                  }
              ]
            }
            '''.stripIndent( )
        ) ).with {
          assertThat( policy != null, "Expected policy" )
          print( "Created policy with details ${policy}" )
          policy.with {
            assertThat( arn != null, "Expected policy arn")
            arn
          }
        }
        print( "Created managed policy with arn ${policyArn2}" )

        print( "Setting policy for user ${testUser}" )
        putUserPolicy( new PutUserPolicyRequest(
            userName: testUser,
            policyName: 'attachment-for-policy-arn',
            policyDocument: """\
            {
              "Version": "2012-10-17",
              "Statement":[
                  {
                    "Effect": "Allow",
                    "Action": [ "iam:Attach*", "iam:Detach*" ],
                    "Resource": "*",
                    "Condition": {
                      "ArnEquals": {
                        "iam:PolicyArn": "${policyArn}"
                      }
                    }
                  }
              ]
            }
            """.stripIndent( )
        ) )

        String groupName = "${NAME_PREFIX}arn-group"
        String roleName = "${NAME_PREFIX}arn-role"
        print( "Creating group for policy arn condition key testing ${groupName}" )
        createGroup( new CreateGroupRequest(
            groupName: groupName
        ))
        print( "Creating role for policy arn condition key testing ${roleName}" )
        createRole( new CreateRoleRequest(
            roleName: roleName,
            assumeRolePolicyDocument: '''\
            {"Statement":[{"Effect":"Allow","Principal":{"Service":["ec2.amazonaws.com"]},"Action":["sts:AssumeRole"]}]}
            '''.stripIndent()
        ))

        getIamClient( testAcctUserCredentials ).with{
          print( "Attaching policy ${policyArn} to group ${groupName}" )
          attachGroupPolicy( new AttachGroupPolicyRequest(
              groupName: groupName,
              policyArn: policyArn
          ) )

          print( "Attaching policy ${policyArn} to role ${roleName}" )
          attachRolePolicy( new AttachRolePolicyRequest(
              roleName: roleName,
              policyArn: policyArn
          ) )

          print( "Attaching policy ${policyArn} to user ${testUser}" )
          attachUserPolicy( new AttachUserPolicyRequest(
              userName: testUser,
              policyArn: policyArn
          ) )

          print( "Detaching policy ${policyArn} from group ${groupName}" )
          detachGroupPolicy( new DetachGroupPolicyRequest(
              groupName: groupName,
              policyArn: policyArn
          ) )

          print( "Detaching policy ${policyArn} from role ${roleName}" )
          detachRolePolicy( new DetachRolePolicyRequest(
              roleName: roleName,
              policyArn: policyArn
          ) )

          print( "Detaching policy ${policyArn} from user ${testUser}" )
          detachUserPolicy( new DetachUserPolicyRequest(
              userName: testUser,
              policyArn: policyArn
          ) )

          print( "Attaching policy ${policyArn2} to group ${groupName}" )
          try {
            attachGroupPolicy(new AttachGroupPolicyRequest(
                groupName: groupName,
                policyArn: policyArn2
            ))
          } catch (AmazonServiceException e) {
            print( "Expected attach policy error for policy with arn not matching condition: ${e}" )
          }

          print( "Attaching policy ${policyArn2} to role ${roleName}" )
          try {
            attachRolePolicy( new AttachRolePolicyRequest(
                roleName: roleName,
                policyArn: policyArn2
            ) )
          } catch (AmazonServiceException e) {
            print( "Expected attach policy error for policy with arn not matching condition: ${e}" )
          }

          print( "Attaching policy ${policyArn2} to user ${testUser}" )
          try {
            attachUserPolicy( new AttachUserPolicyRequest(
                userName: testUser,
                policyArn: policyArn2
            ) )
          } catch (AmazonServiceException e) {
            print( "Expected attach policy error for policy with arn not matching condition: ${e}" )
          }

          void
        }
      }

      print( 'Test complete' )
    } finally {
      // Attempt to clean up anything we created
      cleanupTasks.reverseEach { Runnable cleanupTask ->
        try {
          cleanupTask.run()
        } catch ( NoSuchEntityException e ) {
          print( 'Entity not found during cleanup.' )
        } catch ( AmazonServiceException e ) {
          print( "Service error during cleanup; code: ${e.errorCode}, message: ${e.message}" )
        } catch ( Exception e ) {
          e.printStackTrace()
        }
      }
    }
  }
}
