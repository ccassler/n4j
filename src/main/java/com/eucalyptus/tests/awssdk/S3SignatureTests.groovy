package com.eucalyptus.tests.awssdk

import com.amazonaws.AmazonServiceException
import com.amazonaws.auth.AWSCredentials
import com.amazonaws.services.identitymanagement.model.PutUserPolicyRequest
import com.amazonaws.services.s3.AmazonS3
import com.amazonaws.services.s3.model.Bucket
import com.amazonaws.services.s3.model.ObjectMetadata
import com.amazonaws.services.s3.model.PutObjectRequest
import com.github.sjones4.youcan.youare.YouAre
import org.testng.annotations.AfterClass
import org.testng.annotations.AfterMethod
import org.testng.annotations.BeforeClass
import org.testng.annotations.BeforeMethod
import org.testng.annotations.Test

import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit

import static com.eucalyptus.tests.awssdk.N4j.IAM_ENDPOINT
import static com.eucalyptus.tests.awssdk.N4j.S3_ENDPOINT
import static com.eucalyptus.tests.awssdk.N4j.createAccount
import static com.eucalyptus.tests.awssdk.N4j.createUser
import static com.eucalyptus.tests.awssdk.N4j.eucaUUID
import static com.eucalyptus.tests.awssdk.N4j.getCloudInfo
import static com.eucalyptus.tests.awssdk.N4j.getS3Client
import static com.eucalyptus.tests.awssdk.N4j.getS3SigV4Client
import static com.eucalyptus.tests.awssdk.N4j.getUserCreds
import static com.eucalyptus.tests.awssdk.N4j.getYouAreClient
import static com.eucalyptus.tests.awssdk.N4j.print
import static com.eucalyptus.tests.awssdk.N4j.sleep
import static org.testng.Assert.assertEquals
import static org.testng.Assert.assertTrue
import static org.testng.Assert.fail

/**
 * Test covering HMAC signatures with S3.
 *
 * This covers the following issues:
 *
 *   https://eucalyptus.atlassian.net/browse/EUCA-13052
 *
 */
class S3SignatureTests {
  private String bucketName
  private List<Runnable> cleanupTasks
  private YouAre iam
  private AmazonS3 s3
  private AmazonS3 userS3
  private AmazonS3 userS3v4
  private String account
  private String user = "user"

  @BeforeClass
  public void init() throws Exception {
    print( "### PRE SUITE SETUP - ${getClass().simpleName}")
    try {
      getCloudInfo( )
      account = this.getClass().simpleName.toLowerCase()

      createAccount(account)
      final AWSCredentials adminCredentials = getUserCreds(account,'admin');
      iam = getYouAreClient(adminCredentials, IAM_ENDPOINT)
      s3 = getS3Client(adminCredentials, S3_ENDPOINT)

      createUser(account,user)
      final AWSCredentials userCredentials = getUserCreds(account,user);
      userS3 = getS3Client(userCredentials, S3_ENDPOINT)
      userS3v4 = getS3SigV4Client(userCredentials, S3_ENDPOINT)
    } catch (Exception e) {
      try {
        teardown()
      } catch (Exception ie) {
      }
      throw e
    }
  }

  @AfterClass
  public void teardown() throws Exception {
    print("### POST SUITE CLEANUP - ${getClass().simpleName}")
    N4j.deleteAccount(account)
  }

  @BeforeMethod
  public void setup() throws Exception {
    bucketName = eucaUUID()
    cleanupTasks = []
    Bucket bucket = S3Utils.createBucket(s3, account, bucketName, S3Utils.BUCKET_CREATION_RETRIES)
    cleanupTasks.add{
        print("${account}: Deleting bucket ${bucketName}")
        s3.deleteBucket(bucketName)
    }

    assertTrue(bucket != null, "Invalid reference to bucket")
    assertTrue(bucketName.equals(bucket.name), "Mismatch in bucket names. Expected bucket name to be ${bucketName}, but got ${bucket.name}")
  }

  @AfterMethod
  public void cleanup() throws Exception {
    Collections.reverse(cleanupTasks)
    for (final Runnable cleanupTask : cleanupTasks) {
      try {
        cleanupTask.run()
      } catch (Exception e) {
        print( "Error running clean up task: ${e}")
        e.printStackTrace( )
      }
    }
  }

  @Test
  public void testSignatureV2( ) throws Exception {
    print( "${account}: Putting policy for user ${user}" )
    iam.putUserPolicy( new PutUserPolicyRequest(
        userName: user,
        policyName: 'policy',
        policyDocument: '''\
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action":  "s3:*",
              "Resource": "*",
              "Condition": {
                "StringEquals": {
                  "s3:signatureversion": "AWS",
                  "s3:authType": "REST-HEADER"
                },
                "NumericLessThanEquals": {
                  "s3:signatureAge": "30000"
                },
                "Null": {
                  "s3:x-amz-content-sha256": "true"
                }
              }
            }
          ]
        }
        '''.stripIndent( )
    ) )

    print( "${account}: Listing buckets using signature v2" )
    userS3.listBuckets( )

    try {
      print( "${account}: Listing buckets using signature v4" )
      userS3v4.listBuckets( )
      fail( 'Expected signature v4 auth failure' )
    } catch ( AmazonServiceException e ) {
      print( "${account}: Got expected signature v4 error: ${e}" )
      assertEquals( e.errorCode, 'AccessDenied', "Error code" )
    }
  }

  @Test
  public void testSignatureV4( ) throws Exception {
    print( "${account}: Putting policy for user ${user}" )
    iam.putUserPolicy( new PutUserPolicyRequest(
        userName: user,
        policyName: 'policy',
        policyDocument: '''\
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action":  "s3:*",
              "Resource": "*",
              "Condition": {
                "StringEquals": {
                  "s3:signatureversion": "AWS4-HMAC-SHA256",
                  "s3:authType": "REST-HEADER"
                },
                "StringNotEquals": {
                  "s3:x-amz-content-sha256": "UNSIGNED-PAYLOAD"
                },
                "NumericLessThanEquals": {
                  "s3:signatureAge": "30000"
                }
              }
            }
          ]
        }
        '''.stripIndent( )
    ) )

    print( "${account}: Sleeping to allow iam policy to apply for user ${user}" )
    sleep( 6 )

    print( "${account}: Listing buckets using signature v4" )
    userS3v4.listBuckets( )

    try {
      print( "${account}: Listing buckets using signature v2" )
      userS3.listBuckets( )
      fail( 'Expected signature v2 auth failure' )
    } catch ( AmazonServiceException e ) {
      print( "${account}: Got expected signature v2 error: ${e}" )
      assertEquals( e.errorCode, 'AccessDenied', "Error code" )
    }
  }

  @Test
  public void testSignatureV2QueryString( ) throws Exception {
    final String keyName = "key-1"
    print( "${account}: Putting object to use for testing access ${bucketName}/${keyName}" )
    s3.putObject( new PutObjectRequest(
        bucketName,
        keyName,
        new ByteArrayInputStream( "content".getBytes( StandardCharsets.UTF_8 ) ),
        new ObjectMetadata( ) )
    )
    cleanupTasks.add{
      print("${account}: Deleting object ${bucketName}/${keyName}")
      s3.deleteObject(bucketName, keyName)
    }

    print( "${account}: Putting policy for user ${user}" )
    iam.putUserPolicy( new PutUserPolicyRequest(
        userName: user,
        policyName: 'policy',
        policyDocument: '''\
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action":  "s3:*",
              "Resource": "*",
              "Condition": {
                "StringEquals": {
                  "s3:signatureversion": "AWS",
                  "s3:authType": "REST-QUERY-STRING"
                },
                "Null": {
                  "s3:x-amz-content-sha256": "true",
                  "s3:signatureAge": "true"
                }
              }
            }
          ]
        }
        '''.stripIndent( )
    ) )

    print( "${account}: Sleeping to allow iam policy to apply for user ${user}" )
    sleep( 6 )

    print( "${account}: Generating presigned url" )
    final String url = userS3.generatePresignedUrl(
        bucketName,
        keyName,
        new Date( System.currentTimeMillis( ) + TimeUnit.DAYS.toMillis(1L) )
    )
    print( "${account}: Url: ${url}" )

    print( "${account}: Getting ${bucketName}/${keyName} using presigned url" )
    print( "${account}: Got content: ${new URL(url).getText("UTF-8")}" )
  }

  @Test
  public void testSignatureV4QueryString( ) throws Exception {
    final String keyName = "key-1"
    print( "${account}: Putting object to use for testing access ${bucketName}/${keyName}" )
    s3.putObject( new PutObjectRequest(
        bucketName,
        keyName,
        new ByteArrayInputStream( "content".getBytes( StandardCharsets.UTF_8 ) ),
        new ObjectMetadata( ) )
    )
    cleanupTasks.add{
      print("${account}: Deleting object ${bucketName}/${keyName}")
      s3.deleteObject(bucketName, keyName)
    }

    print( "${account}: Putting policy for user ${user}" )
    iam.putUserPolicy( new PutUserPolicyRequest(
        userName: user,
        policyName: 'policy',
        policyDocument: '''\
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action":  "s3:*",
              "Resource": "*",
              "Condition": {
                "StringEquals": {
                  "s3:signatureversion": "AWS4-HMAC-SHA256",
                  "s3:authType": "REST-QUERY-STRING"
                },
                "NumericLessThanEquals": {
                  "s3:signatureAge": "5000"
                }
              }
            }
          ]
        }
        '''.stripIndent( )
    ) )

    print( "${account}: Sleeping to allow iam policy to apply for user ${user}" )
    sleep( 6 )

    print( "${account}: Generating presigned url" )
    final String url = userS3v4.generatePresignedUrl(
        bucketName,
        keyName,
        new Date( System.currentTimeMillis( ) + TimeUnit.DAYS.toMillis(1L) )
    )
    print( "${account}: Url: ${url}" )

    print( "${account}: Getting ${bucketName}/${keyName} using presigned url" )
    print( "${account}: Got content: ${new URL(url).getText("UTF-8")}" )

    print( "${account}: Sleeping so signature age is exceeded" )
    sleep( 6 )

    try {
      print( "${account}: Getting ${bucketName}/${keyName} using presigned url" )
      print( "${account}: Got content: ${new URL(url).getText("UTF-8")}" )
      fail( "Expected failure due to signature age condition" )
    } catch ( IOException e ) {
      print( "${account}: Got expected error using old presigned url: ${e}" )
    }
  }
}
