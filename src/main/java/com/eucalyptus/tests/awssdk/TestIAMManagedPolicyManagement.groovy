package com.eucalyptus.tests.awssdk

import com.amazonaws.AmazonServiceException
import com.amazonaws.auth.AWSCredentials
import com.amazonaws.auth.AWSCredentialsProvider
import com.amazonaws.internal.StaticCredentialsProvider
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement
import com.amazonaws.services.identitymanagement.model.*
import org.testng.annotations.AfterClass
import org.testng.annotations.Test

import static com.eucalyptus.tests.awssdk.N4j.*

/**
 * Tests management (crud) for IAM managed policies.
 *
 * Related issues:
 *   https://eucalyptus.atlassian.net/browse/EUCA-10773 feature
 *   https://eucalyptus.atlassian.net/browse/EUCA-13069 crud
 *   https://eucalyptus.atlassian.net/browse/EUCA-13070 quotas / errors / formats
 *
 * Related AWS doc:
 *   http://docs.aws.amazon.com/IAM/latest/UserGuide/policies-managed-vs-inline.html
 */
class TestIAMManagedPolicyManagement {

  private final AmazonIdentityManagement testAccountAdminIamClient
  private final String testAcct
  private final testEucalyptusSpecificFunctionality

  // Alternative for testing against aws/iam
//  TestIAMManagedPolicyManagement( ) {
//    this.testAccountAdminIamClient = new AmazonIdentityManagementClient( new BasicAWSCredentials( 'AKI...', '...' ) )
//    this.testAcct = null
//    this.testEucalyptusSpecificFunctionality = false
//    N4j.NAME_PREFIX = eucaUUID() + "-"
//  }

  TestIAMManagedPolicyManagement( ) {
    getCloudInfo( )
    this.testAcct= "${NAME_PREFIX}man-pol-test-acct"
    createAccount(testAcct)
    AWSCredentialsProvider testAcctAdminCredentials = new StaticCredentialsProvider( getUserCreds(testAcct, 'admin') )
    this.testAccountAdminIamClient = getIamClient( testAcctAdminCredentials )
    this.testEucalyptusSpecificFunctionality = true
  }

  @AfterClass
  void tearDownAfterClass( ) {
    deleteAccount( testAcct )
  }

  private AmazonIdentityManagement getIamClient( AWSCredentialsProvider credentialsProvider ) {
    AWSCredentials creds = credentialsProvider.getCredentials( )
    getYouAreClient( creds.AWSAccessKeyId, creds.AWSSecretKey, IAM_ENDPOINT )
  }

  @Test
  void iamManagedPolicyTest( ) {
    testInfo( this.getClass( ).getSimpleName( ) )

    final List<Runnable> cleanupTasks = [] as List<Runnable>
    try {
      testAccountAdminIamClient.with {  iam ->
        String policyName = "${NAME_PREFIX}policy"
        print( "Creating managed policy ${policyName}" )
        String arn = createPolicy( new CreatePolicyRequest(
            policyName: policyName,
            path: '/',
            description: "Policy management test policy ${policyName}",
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
            '''.stripIndent( )
        ) ).with {
          assertThat( policy != null, "Expected policy" )
          print( "Created policy with details ${policy}" )
          policy.with {
            assertThat( arn != null, "Expected policy arn")
            cleanupTasks.add{
              print( "Deleting managed policy ${policyName}" )
              iam.deletePolicy( new DeletePolicyRequest(
                  policyArn: arn
              ) )
            }
            assertThat( policyName == it.policyName, "Unexpected policy name ${it.policyName}" )
            assertThat( policyId != null, "Expected policy identifier")
            assertThat( '/' == path, "Unexpected policy path ${path}" )
            assertThat( defaultVersionId != null, "Expected policy defaultVersionId")
            assertThat( attachmentCount != null, "Expected policy attachmentCount")
            assertThat( description == it.description, "Unexpected policy description ${it.description}")
            assertThat( createDate != null, "Expected policy createDate")
            assertThat( updateDate != null, "Expected policy updateDate")
            arn
          }
        }
        print( "Created policy with arn ${arn}" )

        print( "Getting managed policy ${arn}" )
        getPolicy( new GetPolicyRequest(
            policyArn: arn
        ) ).with {
          print( "Got ${it}" )
          assertThat( policy != null, "Expected policy" )
          policy.with {
            assertThat( arn != null, "Expected policy arn")
            assertThat( policyName == it.policyName, "Unexpected policy name ${it.policyName}" )
            assertThat( policyId != null, "Expected policy identifier")
            assertThat( '/' == path, "Unexpected policy path ${path}" )
            assertThat( defaultVersionId != null, "Expected policy defaultVersionId")
            assertThat( attachmentCount != null, "Expected policy attachmentCount")
            assertThat( attachmentCount == 0, "Expected policy attachmentCount 0, but was ${attachmentCount}")
            assertThat( description == it.description, "Unexpected policy description ${it.description}")
            assertThat( createDate != null, "Expected policy createDate")
            assertThat( updateDate != null, "Expected policy updateDate")
          }
        }

        print( 'Listing all managed policies' )
        listPolicies( new ListPoliciesRequest( scope: 'Local' ) ).with {
          assertThat( policies != null, "Expected policies")
          assertThat( 1 == policies.size(), "Expected 1 policy, but was: ${policies.size()}")
          policies[0].with{
            assertThat( arn != null, "Expected policy arn")
            assertThat( policyName == it.policyName, "Unexpected policy name ${it.policyName}" )
            assertThat( policyId != null, "Expected policy identifier")
            assertThat( '/' == path, "Unexpected policy path ${path}" )
            assertThat( defaultVersionId != null, "Expected policy defaultVersionId")
            assertThat( attachmentCount != null, "Expected policy attachmentCount")
            assertThat( description == it.description, "Unexpected policy description ${it.description}")
            assertThat( createDate != null, "Expected policy createDate")
            assertThat( updateDate != null, "Expected policy updateDate")
          }
        }

        print( 'Listing policies with aws managed scope' )
        listPolicies( new ListPoliciesRequest( scope: 'AWS' ) ).with {
          assertThat( policies != null, "Expected policies")
        }

        print( 'Listing policies with path prefix /no_matches_expected/' )
        listPolicies( new ListPoliciesRequest( pathPrefix: '/no_matches_expected/' ) ).with {
          assertThat( policies != null, "Expected policies")
          assertThat( policies.isEmpty(), "Expected 0 policies")
        }

        print( 'Listing attached policies' )
        listPolicies( new ListPoliciesRequest( onlyAttached: true ) ).with {
          assertThat( policies != null, "Expected policies")
          assertThat( policies.isEmpty(), "Expected 0 policies")
        }

        print( 'Getting account summary' )
        getAccountSummary( ).with {
          print( "Got summary map : ${summaryMap}" )
          assertThat( summaryMap.containsKey( "Policies" ), "Expected Policies summary" )
          Integer policiesCount = summaryMap.get( "Policies" )
          assertThat( 1 == policiesCount, "Expected 1 policy, but was: ${policiesCount}" )
        }

        String invalidPolicyName = "${NAME_PREFIX}invalid-policy"
        Map<String, Object> validParameters = [
            policyName: invalidPolicyName,
            path: '/',
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
            }'''.stripIndent( )
        ]
        [
            [policyName: 'a' * 129], // too long
            [policyName: ''], // too short
            [policyName: '@#$@$'], // invalid characters
            [path: ''], // missing
            [path: 'awerwe' ], // invalid start / end
            [description: 'a' * 1001], // too long
        ].each { invalidParameters ->
          try {
            Map<String, Object> parameters = [:]
            parameters << validParameters
            parameters << invalidParameters
            print( "Testing create policy using invalid parameters: ${parameters}" )
            createPolicy( new CreatePolicyRequest( parameters ) )
            assertThat( false, 'Expected create policy failure due to invalid parameters' )
          } catch (AmazonServiceException e) {
            print( "Create policy error for invalid parameters: ${e}" )
            assertThat(e.statusCode == 400, "Expected status code 400, but was: ${e.statusCode}")
            assertThat(e.errorCode == 'ValidationError', "Expected error code ValidationError, but was: ${e.errorCode}")
          }
        }
        [
            [policyDocument: 'asdf'], // invalid policy
        ].each { invalidParameters ->
          try {
            Map<String, Object> parameters = [:]
            parameters << validParameters
            parameters << invalidParameters
            print( "Testing create policy using invalid parameters: ${parameters}" )
            createPolicy( new CreatePolicyRequest( parameters ) )
            assertThat( false, 'Expected create policy failure due to invalid parameters' )
          } catch (AmazonServiceException e) {
            print( "Create policy error for invalid parameters: ${e}" )
            assertThat(e.statusCode == 400, "Expected status code 400, but was: ${e.statusCode}")
            assertThat(e.errorCode == 'MalformedPolicyDocument', "Expected error code MalformedPolicyDocument, but was: ${e.errorCode}")
          }
        }

        String groupName = "${NAME_PREFIX}group"
        String roleName = "${NAME_PREFIX}role"
        String userName = "${NAME_PREFIX}user"
        print( "Creating group for policy attachment testing ${groupName}" )
        String groupId = createGroup( new CreateGroupRequest(
            groupName: groupName
        )).with {
          group?.groupId
        }
        cleanupTasks.add{
          print( "Deleting group ${groupName}/${groupId}" )
          deleteGroup( new DeleteGroupRequest( groupName: groupName ) )
        }
        print( "Creating role for policy attachment testing ${roleName}" )
        String roleId = createRole( new CreateRoleRequest(
            roleName: roleName,
            assumeRolePolicyDocument: '''\
            {"Statement":[{"Effect":"Allow","Principal":{"Service":["ec2.amazonaws.com"]},"Action":["sts:AssumeRole"]}]}
            '''.stripIndent()
        )).with {
          role?.roleId
        }
        cleanupTasks.add{
          print( "Deleting role ${roleName}/${roleId}" )
          deleteRole( new DeleteRoleRequest( roleName: roleName ) )
        }
        print( "Creating user for policy attachment testing ${userName}" )
        String userId = createUser( new CreateUserRequest(
            userName: userName
        )).with {
          user?.userId
        }
        cleanupTasks.add{
          print( "Deleting user ${userName}/${userId}" )
          deleteUser( new DeleteUserRequest( userName: userName ) )
        }

        String invalidArn = arn.replace( policyName, invalidPolicyName )
        print( "Listing entities for invalid policy ${invalidArn}" )
        try {
          listEntitiesForPolicy( new ListEntitiesForPolicyRequest(
              policyArn: invalidArn
          ) )
          assertThat( false, 'Expected failure for invalid arn' )
        } catch (AmazonServiceException e) {
          print( "List entities for policy error for invalid arn: ${e}" )
          assertThat(e.statusCode == 404, "Expected status code 404, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'NoSuchEntity', "Expected error code NoSuchEntity, but was: ${e.errorCode}")
        }

        print( "Attaching policy ${arn} to group ${groupName}" )
        attachGroupPolicy( new AttachGroupPolicyRequest(
            groupName: groupName,
            policyArn: arn
        ) )
        print( "Attaching invalid policy ${invalidArn} to group ${groupName}" )
        try {
          attachGroupPolicy( new AttachGroupPolicyRequest(
              groupName: groupName,
              policyArn: invalidArn
          ) )
          assertThat( false, 'Expected failure for invalid arn' )
        } catch (AmazonServiceException e) {
          print( "Attach invalid policy error for group: ${e}" )
          assertThat(e.statusCode == 404, "Expected status code 404, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'NoSuchEntity', "Expected error code NoSuchEntity, but was: ${e.errorCode}")
        }
        print( "Listing attached policies for group ${groupName}" )
        listAttachedGroupPolicies( new ListAttachedGroupPoliciesRequest(
            groupName: groupName
        ) ).with {
          assertThat( attachedPolicies != null, "Expected attached policies" )
          assertThat( attachedPolicies.size( ) == 1, "Expected 1 attached policy, but was: ${attachedPolicies.size( )}" )
          attachedPolicies[0].with{
            assertThat( arn == policyArn, "Expected arn ${arn}, but was: ${policyArn}" )
            assertThat( policyName == it.policyName, "Expected name ${policyName}, but was: ${it.policyName}" )
          }
        }
        print( "Listing attached policies for invalid group invalid-name" )
        try {
          listAttachedGroupPolicies( new ListAttachedGroupPoliciesRequest(
              groupName: 'invalid-name',
          ) )
          assertThat( false, 'Expected failure for invalid name' )
        } catch (AmazonServiceException e) {
          print( "List attached policies error for invalid name: ${e}" )
          assertThat(e.statusCode == 404, "Expected status code 404, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'NoSuchEntity', "Expected error code NoSuchEntity, but was: ${e.errorCode}")
        }
        listAttachedGroupPolicies( new ListAttachedGroupPoliciesRequest(
            groupName: groupName,
            pathPrefix: '/no_policies_here/'
        ) ).with {
          assertThat(attachedPolicies != null, "Expected attached policies")
          assertThat(attachedPolicies.isEmpty(), "Expected 0 attached policy, but was: ${attachedPolicies.size()}")
        }
        print( "Listing entities for policy ${arn}" )
        listEntitiesForPolicy( new ListEntitiesForPolicyRequest(
          policyArn: arn
        ) ).with {
          assertThat( policyGroups != null, "Expected policy groups" )
          assertThat( policyGroups.size( ) == 1, "Expected 1 group, but was: ${policyGroups.size( )}" )
          policyGroups[0].with {
            assertThat( groupName == it.groupName, "Expected group name ${groupName}, but was: ${it.groupName}" )
            assertThat( groupId == it.groupId, "Expected group id ${groupId}, but was: ${it.groupId}" )
          }
          assertThat( policyRoles != null, "Expected policy roles" )
          assertThat( policyRoles.isEmpty(), "Expected 0 roles, but was: ${policyRoles.size( )}" )
          assertThat( policyUsers != null, "Expected policy users" )
          assertThat( policyUsers.isEmpty(), "Expected 0 users, but was: ${policyUsers.size( )}" )
        }
        print( "Getting policy to check attachment count is 1" )
        getPolicy( new GetPolicyRequest( policyArn: arn ) ).with {
          assertThat( policy != null, 'Expected policy' )
          policy.with {
            assertThat( attachmentCount != null, 'Expected policy attachment count' )
            assertThat( attachmentCount == 1, "Expected policy attachment count 1, but was: ${attachmentCount}" )
          }
        }
        print( "Deleting policy ${arn} should fail due to attached group" )
        try {
          iam.deletePolicy( new DeletePolicyRequest( policyArn: arn ) )
          assertThat( false, 'Expected delete failure due to attachment' )
        } catch (AmazonServiceException e) {
          print( "Delete policy error for attached group: ${e}" )
          assertThat(e.statusCode == 409, "Expected status code 409, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'DeleteConflict', "Expected error code DeleteConflict, but was: ${e.errorCode}")
        }
        print( "Attaching already attached policy ${arn} to group ${groupName}" )
        attachGroupPolicy( new AttachGroupPolicyRequest(
            groupName: groupName,
            policyArn: arn
        ) )
        print( "Detaching policy ${arn} from group ${groupName}" )
        detachGroupPolicy( new DetachGroupPolicyRequest(
            groupName: groupName,
            policyArn: arn
        ) )
        print( "Detaching already detached policy ${arn} from group ${groupName}" )
        try {
          detachGroupPolicy( new DetachGroupPolicyRequest(
              groupName: groupName,
              policyArn: arn
          ) )
          assertThat( false, 'Expected detach failure due to already detached' )
        } catch (AmazonServiceException e) {
          print( "Detach policy error for already detached group: ${e}" )
          assertThat(e.statusCode == 404, "Expected status code 404, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'NoSuchEntity', "Expected error code NoSuchEntity, but was: ${e.errorCode}")
        }
        print( "Detaching invalid policy ${invalidArn} from group ${groupName}" )
        try {
          detachGroupPolicy( new DetachGroupPolicyRequest(
              groupName: groupName,
              policyArn: invalidArn
          ) )
          assertThat( false, 'Expected error for invalid arn on detach' )
        } catch (AmazonServiceException e) {
          print( "Detach invalid policy error for group: ${e}" )
          assertThat(e.statusCode == 404, "Expected status code 404, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'NoSuchEntity', "Expected error code NoSuchEntity, but was: ${e.errorCode}")
        }
        print( "Getting policy to check attachment count is 0" )
        getPolicy( new GetPolicyRequest( policyArn: arn ) ).with {
          assertThat( policy != null, 'Expected policy' )
          policy.with {
            assertThat( attachmentCount != null, 'Expected policy attachment count' )
            assertThat( attachmentCount == 0, "Expected policy attachment count 0, but was: ${attachmentCount}" )
          }
        }

        print( "Attaching policy ${arn} to role ${roleName}" )
        attachRolePolicy( new AttachRolePolicyRequest(
            roleName: roleName,
            policyArn: arn
        ) )
        print( "Attaching invalid policy ${invalidArn} to role ${roleName}" )
        try {
          attachRolePolicy( new AttachRolePolicyRequest(
              roleName: roleName,
              policyArn: invalidArn
          ) )
          assertThat( false, 'Expected error for invalid arn' )
        } catch (AmazonServiceException e) {
          print( "Attach invalid policy error for role: ${e}" )
          assertThat(e.statusCode == 404, "Expected status code 404, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'NoSuchEntity', "Expected error code NoSuchEntity, but was: ${e.errorCode}")
        }
        print( "Listing attached policies for role ${roleName}" )
        listAttachedRolePolicies( new ListAttachedRolePoliciesRequest(
            roleName: roleName
        ) ).with {
          assertThat( attachedPolicies != null, "Expected attached policies" )
          assertThat( attachedPolicies.size( ) == 1, "Expected 1 attached policy, but was: ${attachedPolicies.size( )}" )
          attachedPolicies[0].with{
            assertThat( arn == policyArn, "Expected arn ${arn}, but was: ${policyArn}" )
            assertThat( policyName == it.policyName, "Expected name ${policyName}, but was: ${it.policyName}" )
          }
        }
        print( "Listing attached policies for invalid role invalid-name" )
        try {
          listAttachedRolePolicies( new ListAttachedRolePoliciesRequest(
              roleName: 'invalid-name',
          ) )
          assertThat( false, 'Expected failure for invalid name' )
        } catch (AmazonServiceException e) {
          print( "List attached policies error for invalid name: ${e}" )
          assertThat(e.statusCode == 404, "Expected status code 404, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'NoSuchEntity', "Expected error code NoSuchEntity, but was: ${e.errorCode}")
        }
        listAttachedRolePolicies( new ListAttachedRolePoliciesRequest(
            roleName: roleName,
            pathPrefix: '/no_policies_here/'
        ) ).with {
          assertThat(attachedPolicies != null, "Expected attached policies")
          assertThat(attachedPolicies.isEmpty(), "Expected 0 attached policy, but was: ${attachedPolicies.size()}")
        }
        print( "Listing entities for policy ${arn}" )
        listEntitiesForPolicy( new ListEntitiesForPolicyRequest(
            policyArn: arn
        ) ).with {
          assertThat( policyGroups != null, "Expected policy groups" )
          assertThat( policyGroups.isEmpty(), "Expected 0 groups, but was: ${policyGroups.size( )}" )
          assertThat( policyRoles != null, "Expected policy roles" )
          assertThat( policyRoles.size( ) == 1, "Expected 1 role, but was: ${policyGroups.size( )}" )
          policyRoles[0].with {
            assertThat( roleName == it.roleName, "Expected role name ${roleName}, but was: ${it.roleName}" )
            assertThat( roleId == it.roleId, "Expected role id ${roleId}, but was: ${it.roleId}" )
          }
          assertThat( policyUsers != null, "Expected policy users" )
          assertThat( policyUsers.isEmpty(), "Expected 0 users, but was: ${policyUsers.size( )}" )
        }
        print( "Deleting policy ${arn} should fail due to attached role" )
        try {
          iam.deletePolicy( new DeletePolicyRequest( policyArn: arn ) )
          assertThat( false, 'Expected delete failure due to attachment' )
        } catch (AmazonServiceException e) {
          print( "Delete policy error for attached role: ${e}" )
          assertThat(e.statusCode == 409, "Expected status code 409, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'DeleteConflict', "Expected error code DeleteConflict, but was: ${e.errorCode}")
        }
        print( "Attaching already attached policy ${arn} to role ${roleName}" )
        attachRolePolicy( new AttachRolePolicyRequest(
            roleName: roleName,
            policyArn: arn
        ) )
        print( "Detaching policy ${arn} from role ${groupName}" )
        detachRolePolicy( new DetachRolePolicyRequest(
            roleName: roleName,
            policyArn: arn
        ) )
        print( "Detaching already detached policy ${arn} from role ${roleName}" )
        try {
          detachRolePolicy( new DetachRolePolicyRequest(
              roleName: roleName,
              policyArn: arn
          ) )
          assertThat( false, 'Expected detach failure due to already detached' )
        } catch (AmazonServiceException e) {
          print( "Detach policy error for already detached role: ${e}" )
          assertThat(e.statusCode == 404, "Expected status code 404, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'NoSuchEntity', "Expected error code NoSuchEntity, but was: ${e.errorCode}")
        }
        print( "Detaching invalid policy ${invalidArn} from role ${roleName}" )
        try {
          detachRolePolicy( new DetachRolePolicyRequest(
              roleName: roleName,
              policyArn: invalidArn
          ) )
          assertThat( false, 'Expected error for invalid arn on detach' )
        } catch (AmazonServiceException e) {
          print( "Detach invalid policy error for role: ${e}" )
          assertThat(e.statusCode == 404, "Expected status code 404, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'NoSuchEntity', "Expected error code NoSuchEntity, but was: ${e.errorCode}")
        }

        print( "Attaching policy ${arn} to user ${userName}" )
        attachUserPolicy( new AttachUserPolicyRequest(
            userName: userName,
            policyArn: arn
        ) )
        print( "Attaching invalid policy ${invalidArn} to user ${userName}" )
        try {
          attachUserPolicy( new AttachUserPolicyRequest(
              userName: userName,
              policyArn: invalidArn
          ) )
          assertThat( false, 'Expected error for invalid arn' )
        } catch (AmazonServiceException e) {
          print( "Attach invalid policy error for user: ${e}" )
          assertThat(e.statusCode == 404, "Expected status code 404, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'NoSuchEntity', "Expected error code NoSuchEntity, but was: ${e.errorCode}")
        }
        print( "Listing attached policies for user ${userName}" )
        listAttachedUserPolicies( new ListAttachedUserPoliciesRequest(
            userName: userName
        ) ).with {
          assertThat( attachedPolicies != null, "Expected attached policies" )
          assertThat( attachedPolicies.size( ) == 1, "Expected 1 attached policy, but was: ${attachedPolicies.size( )}" )
          attachedPolicies[0].with{
            assertThat( arn == policyArn, "Expected arn ${arn}, but was: ${policyArn}" )
            assertThat( policyName == it.policyName, "Expected name ${policyName}, but was: ${it.policyName}" )
          }
        }
        print( "Listing attached policies for invalid user invalid-name" )
        try {
          listAttachedUserPolicies( new ListAttachedUserPoliciesRequest(
              userName: 'invalid-name',
          ) )
          assertThat( false, 'Expected failure for invalid name' )
        } catch (AmazonServiceException e) {
          print( "List attached policies error for invalid name: ${e}" )
          assertThat(e.statusCode == 404, "Expected status code 404, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'NoSuchEntity', "Expected error code NoSuchEntity, but was: ${e.errorCode}")
        }
        listAttachedUserPolicies( new ListAttachedUserPoliciesRequest(
            userName: userName,
            pathPrefix: '/no_policies_here/'
        ) ).with {
          assertThat(attachedPolicies != null, "Expected attached policies")
          assertThat(attachedPolicies.isEmpty(), "Expected 0 attached policy, but was: ${attachedPolicies.size()}")
        }
        print( "Listing entities for policy ${arn}" )
        listEntitiesForPolicy( new ListEntitiesForPolicyRequest(
            policyArn: arn
        ) ).with {
          assertThat( policyGroups != null, "Expected policy groups" )
          assertThat( policyGroups.isEmpty(), "Expected 0 groups, but was: ${policyGroups.size( )}" )
          assertThat( policyRoles != null, "Expected policy roles" )
          assertThat( policyRoles.isEmpty(), "Expected 0 roles, but was: ${policyGroups.size( )}" )
          assertThat( policyUsers != null, "Expected policy users" )
          assertThat( policyUsers.size( ) == 1, "Expected 1 users, but was: ${policyUsers.size( )}" )
          policyUsers[0].with {
            assertThat( userName == it.userName, "Expected user name ${userName}, but was: ${it.userName}" )
            assertThat( userId == it.userId, "Expected user id ${userId}, but was: ${it.userId}" )
          }
        }
        print( "Deleting policy ${arn} should fail due to attached user" )
        try {
          iam.deletePolicy( new DeletePolicyRequest( policyArn: arn ) )
          assertThat( false, 'Expected delete failure due to attachment' )
        } catch (AmazonServiceException e) {
          print( "Delete policy error for attached user: ${e}" )
          assertThat(e.statusCode == 409, "Expected status code 409, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'DeleteConflict', "Expected error code DeleteConflict, but was: ${e.errorCode}")
        }
        print( "Attaching already attached policy ${arn} to user ${userName}" )
        attachUserPolicy( new AttachUserPolicyRequest(
            userName: userName,
            policyArn: arn
        ) )
        print( "Detaching policy ${arn} from user ${userName}" )
        detachUserPolicy( new DetachUserPolicyRequest(
            userName: userName,
            policyArn: arn
        ) )
        print( "Detaching already detached policy ${arn} from user ${userName}" )
        try {
          detachUserPolicy( new DetachUserPolicyRequest(
              userName: userName,
              policyArn: arn
          ) )
          assertThat( false, 'Expected detach failure due to already detached' )
        } catch (AmazonServiceException e) {
          print( "Detach policy error for already detached user: ${e}" )
          assertThat(e.statusCode == 404, "Expected status code 404, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'NoSuchEntity', "Expected error code NoSuchEntity, but was: ${e.errorCode}")
        }
        print( "Detaching invalid policy ${invalidArn} from user ${userName}" )
        try {
          detachUserPolicy( new DetachUserPolicyRequest(
              userName: userName,
              policyArn: invalidArn
          ) )
          assertThat( false, 'Expected error for invalid arn on detach' )
        } catch (AmazonServiceException e) {
          print( "Detach invalid policy error for user: ${e}" )
          assertThat(e.statusCode == 404, "Expected status code 404, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'NoSuchEntity', "Expected error code NoSuchEntity, but was: ${e.errorCode}")
        }

        if ( testEucalyptusSpecificFunctionality ) {
          print( "Attaching policy ${arn} to user ${userName} to use for testing administrative detach" )
          attachUserPolicy( new AttachUserPolicyRequest(
              userName: userName,
              policyArn: arn
          ) )

          print( "Detaching policy ${arn} from user ${userName} as administrator" )
          youAre.detachUserPolicy( new DetachUserPolicyRequest(
              userName: userName,
              policyArn: arn
          ).with {
            putCustomQueryParameter( 'DelegateAccount', testAcct )
            it
          } )

          print( "Deleting policy ${arn} as administrator" )
          youAre.deletePolicy( new DeletePolicyRequest(
              policyArn: arn
          ).with {
            putCustomQueryParameter( 'DelegateAccount', testAcct )
            it
          } )
        } else { // non-euca alternative
          print( "Deleting policy ${arn}" )
          iam.deletePolicy( new DeletePolicyRequest( policyArn: arn ) )
        }

        print( 'Getting account summary' )
        getAccountSummary( ).with {
          print( "Got summary map : ${summaryMap}" )

          assertThat( summaryMap.containsKey( "Policies" ), "Expected Policies summary" )
          Integer policiesCount = summaryMap.get( "Policies" )
          assertThat( 0 == policiesCount, "Expected 0 policies, but was: ${policiesCount}" )

          assertThat( summaryMap.containsKey( "PolicySizeQuota" ), "Expected PolicySizeQuota summary" )
          Integer policySize = summaryMap.get( "PolicySizeQuota" )
          assertThat( policySize > 0, "Expected PolicySizeQuota > 0, but was: ${policySize}" )

          [ 'AttachedPoliciesPerGroupQuota', 'AttachedPoliciesPerRoleQuota', 'AttachedPoliciesPerUserQuota' ].each {
            attachmentSummaryItem ->
              assertThat( summaryMap.containsKey( attachmentSummaryItem ), "Expected ${attachmentSummaryItem} summary" )
              Integer attachmentPerEntity = summaryMap.get( attachmentSummaryItem )
              assertThat( attachmentPerEntity > 0, "Expected ${attachmentSummaryItem} > 0, but was: ${attachmentPerEntity}" )
          }
        }

        // Test creating policy versions up to limit, deletion and listing
        String versionsPolicyName = "${NAME_PREFIX}policy-versions"
        print( "Creating managed policy ${versionsPolicyName}" )
        String versionsArn = createPolicy( new CreatePolicyRequest(
            policyName: versionsPolicyName,
            description: "Policy management test policy ${versionsPolicyName}",
            policyDocument: '''\
            {
              "Version": "2012-10-17",
              "Statement":[
                  {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                  }
              ]
            }
            '''.stripIndent( )
        ) ).with {
          assertThat( policy != null, "Expected policy" )
          print( "Created policy with details ${policy}" )
          policy.with { policy ->
            assertThat( policy.arn != null, "Expected policy arn")
            cleanupTasks.add{
              print( "Deleting managed policy ${versionsPolicyName}" )
              iam.deletePolicy( new DeletePolicyRequest(
                  policyArn: policy.arn
              ) )
            }
            assertThat( '/' == path, "Unexpected policy path ${path}" )
            policy.arn
          }
        }
        print( "Created policy with arn ${versionsArn}" )

        print( "Creating 4 policy versions" )
        ( 1..4 ).each{ sid ->
          createPolicyVersion( new CreatePolicyVersionRequest(
              policyArn: versionsArn,
              policyDocument: """\
              {
                "Version": "2012-10-17",
                "Statement": { "Sid": "sid${sid}", "Effect": "Allow", "Action": "ec2:*", "Resource": "*" }
              }
              """.stripIndent( )
          ) )
        }
        print( "Creating 6th policy version to test limit" )
        try {
          createPolicyVersion( new CreatePolicyVersionRequest(
              policyArn: versionsArn,
              policyDocument: """\
              { "Version": "2012-10-17", "Statement": { "Effect": "Allow", "Action": "ec2:*", "Resource": "*" } }
            """.stripIndent( )
          ) )
          assertThat( false, 'Expected creation of policy version beyond limit to fail' )
        } catch (AmazonServiceException e) {
          print( "Expected failure for creating policy version beyond limit: ${e}" )
          assertThat(e.statusCode == 409, "Expected status code 409, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'LimitExceeded', "Expected error code LimitExceeded, but was: ${e.errorCode}")
        }

        print( "Deleting policy versions v3,v4" )
        deletePolicyVersion( new DeletePolicyVersionRequest(
            policyArn: versionsArn,
            versionId: 'v3'
        ) )
        deletePolicyVersion( new DeletePolicyVersionRequest(
            policyArn: versionsArn,
            versionId: 'v4'
        ) )

        print( "Listing policy versions for ${versionsArn}" )
        listPolicyVersions( new ListPolicyVersionsRequest( policyArn: versionsArn ) ).with {
          assertThat( versions != null, 'Expected versions' )
          assertThat( versions.size() == 3, "Expected 3 versions, but was: ${versions.size()}")
          versions.each { version ->
            assertThat( version.document == null, 'Unexpected document' )
            assertThat( version.versionId != null, 'Expected versions id' )
            assertThat( version.createDate != null, 'Expected create date' )
            assertThat( version.isDefaultVersion != null, 'Expected default version flag' )
            if ( 'v1' == version.versionId ) {
              assertThat( version.isDefaultVersion, 'Expected default version for v1' )
            } else {
              assertThat(!version.isDefaultVersion, "Expected not default version for ${version.versionId}" )
            }
          }
        }

        print( "Setting default policy version for ${versionsArn}" )
        setDefaultPolicyVersion( new SetDefaultPolicyVersionRequest(
            policyArn: versionsArn,
            versionId: 'v5'
        ) )
        print( "Listing policy versions for ${versionsArn} to check v5 is default" )
        listPolicyVersions( new ListPolicyVersionsRequest( policyArn: versionsArn ) ).with {
          assertThat( versions != null, 'Expected versions' )
          versions.each { version ->
            assertThat( version.versionId != null, 'Expected versions id' )
            if ( 'v5' == version.versionId ) {
              assertThat( version.isDefaultVersion, 'Expected default version for v5' )
            } else {
              assertThat(!version.isDefaultVersion, "Expected not default version for ${version.versionId}" )
            }
          }
        }
        print( "Getting policy ${versionsArn} to check default" )
        getPolicy( new GetPolicyRequest(
            policyArn: versionsArn,
        ) ).with {
          assertThat( policy != null, 'Expected policy' )
          assertThat( policy.defaultVersionId != null, 'Expected policy default version id' )
          assertThat( policy.defaultVersionId == 'v5',
              "Expected policy default version id v5, but was: ${policy.defaultVersionId}" )
        }

        print( "Deleting default policy version for ${versionsArn}" )
        try {
          deletePolicyVersion( new DeletePolicyVersionRequest(
              policyArn: versionsArn,
              versionId: 'v5'
          ) )
          assertThat( false, 'Expected deletion of default policy version to fail' )
        } catch (AmazonServiceException e) {
          print( "Expected failure for deleting default policy version: ${e}" )
          assertThat(e.statusCode == 409, "Expected status code 409, but was: ${e.statusCode}")
          assertThat(e.errorCode == 'DeleteConflict', "Expected error code DeleteConflict, but was: ${e.errorCode}")
        }

        print( "Getting policy version v5 for ${versionsArn}" )
        getPolicyVersion( new GetPolicyVersionRequest(
            policyArn: versionsArn,
            versionId: 'v5'
        ) ).with {
          print( "Got policy version: ${policyVersion}" )
          assertThat( policyVersion != null, 'Expected policy version' )
          policyVersion.with {
            assertThat( document != null, 'Expected document' )
            assertThat( versionId != null, 'Expected versions id' )
            assertThat( createDate != null, 'Expected create date' )
            assertThat( isDefaultVersion != null, 'Expected default version flag' )
          }
        }

        print( "Setting default policy version to v1 for ${versionsArn}" )
        setDefaultPolicyVersion( new SetDefaultPolicyVersionRequest(
            policyArn: versionsArn,
            versionId: 'v1'
        ) )
        print( "Deleting policy versions v2,v5" )
        deletePolicyVersion( new DeletePolicyVersionRequest(
            policyArn: versionsArn,
            versionId: 'v2'
        ) )
        deletePolicyVersion( new DeletePolicyVersionRequest(
            policyArn: versionsArn,
            versionId: 'v5'
        ) )
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
