package com.eucalyptus.tests.awssdk

import com.amazonaws.AmazonServiceException
import com.amazonaws.auth.AWSCredentials
import com.amazonaws.auth.AWSCredentialsProvider
import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.internal.StaticCredentialsProvider
import com.amazonaws.services.identitymanagement.model.*
import com.github.sjones4.youcan.youare.YouAre
import com.github.sjones4.youcan.youare.model.PutAccountPolicyRequest
import org.testng.annotations.AfterClass
import org.testng.annotations.Test

import static com.eucalyptus.tests.awssdk.N4j.*

/**
 * Tests management (crud) for IAM managed policies.
 *
 * Related issues:
 *   https://eucalyptus.atlassian.net/browse/EUCA-10773 feature
 *   https://eucalyptus.atlassian.net/browse/EUCA-13070 quotas / errors / formats
 *
 * Related AWS doc:
 *   http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-limits.html
 *   http://docs.aws.amazon.com/IAM/latest/UserGuide/policies-managed-vs-inline.html
 */
class TestIAMManagedPolicyLimits {

  private final AWSCredentialsProvider testAcctAdminCredentials
  private final String testAcct

  TestIAMManagedPolicyLimits( ) {
    getCloudInfo( )
    this.testAcct= "${NAME_PREFIX}man-pol-test-limits"
    createAccount(testAcct)
    this.testAcctAdminCredentials = new StaticCredentialsProvider( getUserCreds(testAcct, 'admin') )
  }

  @AfterClass
  void tearDownAfterClass( ) {
    deleteAccount( testAcct )
  }

  private YouAre getIamClient(
      AWSCredentialsProvider credentialsProvider = testAcctAdminCredentials
  ) {
    AWSCredentials creds = credentialsProvider.getCredentials( );
    getYouAreClient( creds.AWSAccessKeyId, creds.AWSSecretKey, IAM_ENDPOINT )
  }

  @Test
  void iamManagedPolicyTest( ) {
    testInfo( this.getClass( ).getSimpleName( ) )

    final List<Runnable> cleanupTasks = [] as List<Runnable>
    try {
      getIamClient( ).with { iam ->
        print( 'Getting account summary for limits' )
        int groupPolicyAttachmentLimit = 0
        int rolePolicyAttachmentLimit = 0
        int userPolicyAttachmentLimit = 0
        getAccountSummary( ).with {
          print( "Got summary map : ${summaryMap}" )

          assertThat( summaryMap.containsKey( "AttachedPoliciesPerGroupQuota" ), "Expected AttachedPoliciesPerGroupQuota summary" )
          assertThat( summaryMap.containsKey( "AttachedPoliciesPerRoleQuota" ), "Expected AttachedPoliciesPerRoleQuota summary" )
          assertThat( summaryMap.containsKey( "AttachedPoliciesPerUserQuota" ), "Expected AttachedPoliciesPerUserQuota summary" )

          groupPolicyAttachmentLimit = summaryMap.get( 'AttachedPoliciesPerGroupQuota' )
          rolePolicyAttachmentLimit = summaryMap.get( 'AttachedPoliciesPerRoleQuota' )
          userPolicyAttachmentLimit = summaryMap.get( 'AttachedPoliciesPerUserQuota' )
        }

        int maxPolicyAttachment =
            Math.max( groupPolicyAttachmentLimit, Math.max( rolePolicyAttachmentLimit, userPolicyAttachmentLimit ) )

        print( 'Putting policy quota for account' )
        getIamClient( new StaticCredentialsProvider( new BasicAWSCredentials( ACCESS_KEY, SECRET_KEY ) ) ).with{
          putAccountPolicy( new PutAccountPolicyRequest(
              accountName: testAcct,
              policyName: 'policy',
              policyDocument: """\
            {
              "Version": "2012-10-17",
              "Statement":[
                  {
                    "Effect": "Limit",
                    "Action": "iam:CreatePolicy",
                    "Resource": "*",
                    "Condition":{
                      "NumericLessThanEquals":{
                        "iam:quota-policynumber":"${maxPolicyAttachment+1}"
                      }
                    }
                  }
              ]
            }
            """.stripIndent( )
          ) )
        }

        String groupName = "${NAME_PREFIX}group"
        String roleName = "${NAME_PREFIX}role"
        String userName = "${NAME_PREFIX}user"
        print( "Creating group for policy attachment testing ${groupName}" )
        createGroup( new CreateGroupRequest(
            groupName: groupName
        )).with {
          group?.groupId
        }
        print( "Creating role for policy attachment testing ${roleName}" )
        createRole( new CreateRoleRequest(
            roleName: roleName,
            assumeRolePolicyDocument: '''\
            {"Statement":[{"Effect":"Allow","Principal":{"Service":["ec2.amazonaws.com"]},"Action":["sts:AssumeRole"]}]}
            '''.stripIndent()
        )).with {
          role?.roleId
        }
        print( "Creating user for policy attachment testing ${userName}" )
        createUser( new CreateUserRequest(
            userName: userName
        )).with {
          user?.userId
        }

        String policyName = "${NAME_PREFIX}policy"
        List<String> policyArns = ( 1..(maxPolicyAttachment+1) ).collect { policyNumber ->
          print("Creating managed policy ${policyName}-${policyNumber}")
          createPolicy(new CreatePolicyRequest(
              policyName: "${policyName}-${policyNumber}",
              description: "Policy management test policy ${policyName}-${policyNumber}",
              policyDocument: '''\
            {
              "Version": "2012-10-17",
              "Statement":[
                  {
                    "Effect": "Allow",
                    "Action": "ec2:*",
                    "Resource": "*"
                  }
              ]
            }
            '''.stripIndent()
          )).with {
            String arn = policy.arn
            assertThat(arn != null, "Expected policy arn")
            print("Created policy with arn ${arn}")
            cleanupTasks.add{
              print( "Deleting managed policy ${policyName}-${policyNumber}" )
              iam.deletePolicy( new DeletePolicyRequest(
                  policyArn: arn
              ) )
            }
            arn
          }
        }

        print( "Sleeping 5 seconds to allow account quota to be applied" )
        sleep( 5 )

        print( "Creating policy beyond quota" )
        try {
          createPolicy( new CreatePolicyRequest(
              policyName: 'policy',
              policyDocument: '''\
            {
              "Version": "2012-10-17",
              "Statement":[
                  {
                    "Effect": "Allow",
                    "Action": "ec2:*",
                    "Resource": "*"
                  }
              ]
            }
            '''.stripIndent()
          ) )
          assertThat( false, 'Expected failure creating policy beyond quota' )
        } catch (AmazonServiceException e) {
          print("Create policy beyond quota error: ${e}")
          assertThat(e.statusCode == 409, "Expected status code 409, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'LimitExceeded', "Expected error code LimitExceeded, but was: ${e.errorCode}")
        }

        ( 1..(groupPolicyAttachmentLimit) ).each{ attachmentNumber ->
          print( "Attaching group policy ${attachmentNumber}" )
          attachGroupPolicy( new AttachGroupPolicyRequest(
              groupName: groupName,
              policyArn: policyArns[attachmentNumber-1]
          ) )
        }

        ( 1..(rolePolicyAttachmentLimit) ).each{ attachmentNumber ->
          print( "Attaching role policy ${attachmentNumber}" )
          attachRolePolicy( new AttachRolePolicyRequest(
              roleName: roleName,
              policyArn: policyArns[attachmentNumber-1]
          ) )
        }


        ( 1..(userPolicyAttachmentLimit) ).each{ attachmentNumber ->
          print( "Attaching user policy ${attachmentNumber}" )
          attachUserPolicy( new AttachUserPolicyRequest(
              userName: userName,
              policyArn: policyArns[attachmentNumber-1]
          ) )
        }

        try {
          print( "Attaching group policy beyond attachment limit" )
          attachGroupPolicy( new AttachGroupPolicyRequest(
              groupName: groupName,
              policyArn: policyArns[groupPolicyAttachmentLimit]
          ) )
          assertThat( false, 'Expected policy attach failure due to quota exceeded' )
        } catch (AmazonServiceException e) {
          print("Attach group policy beyond attachment limit error: ${e}")
          assertThat(e.statusCode == 409, "Expected status code 409, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'LimitExceeded', "Expected error code LimitExceeded, but was: ${e.errorCode}")
        }

        try {
          print( "Attaching role policy beyond attachment limit" )
          attachRolePolicy( new AttachRolePolicyRequest(
              roleName: roleName,
              policyArn: policyArns[rolePolicyAttachmentLimit]
          ) )
          assertThat( false, 'Expected policy attach failure due to quota exceeded' )
        } catch (AmazonServiceException e) {
          print("Attach role policy beyond attachment limit error: ${e}")
          assertThat(e.statusCode == 409, "Expected status code 409, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'LimitExceeded', "Expected error code LimitExceeded, but was: ${e.errorCode}")
        }

        try {
          print( "Attaching user policy beyond attachment limit" )
          attachUserPolicy( new AttachUserPolicyRequest(
              userName: userName,
              policyArn: policyArns[userPolicyAttachmentLimit]
          ) )
          assertThat( false, 'Expected policy attach failure due to quota exceeded' )
        } catch (AmazonServiceException e) {
          print("Attach user policy beyond attachment limit error: ${e}")
          assertThat(e.statusCode == 409, "Expected status code 409, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'LimitExceeded', "Expected error code LimitExceeded, but was: ${e.errorCode}")
        }

        void
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
