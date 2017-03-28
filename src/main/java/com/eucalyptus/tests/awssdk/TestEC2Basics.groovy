package com.eucalyptus.tests.awssdk

import com.amazonaws.AmazonServiceException
import com.amazonaws.auth.AWSStaticCredentialsProvider
import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.client.builder.AwsClientBuilder
import com.amazonaws.services.ec2.AmazonEC2
import com.amazonaws.services.ec2.AmazonEC2Client
import com.amazonaws.services.ec2.model.*
import org.testng.annotations.BeforeClass
import org.testng.annotations.Test

import java.util.concurrent.TimeUnit

import static com.eucalyptus.tests.awssdk.N4j.*;


/**
 * Test basic EC2 functionality
 */
class TestEC2Basics {

  @BeforeClass
  void init( ) {
    getCloudInfo( )
  }

  @Test( enabled = false ) // Enable when functionality is fixed
  void testUnknownAccessKeyError( ) throws Exception {
    testInfo("${this.getClass().simpleName}.testUnknownAccessKeyError");

    try {
      final AmazonEC2 client = AmazonEC2Client.builder( )
        .withCredentials( new AWSStaticCredentialsProvider( new BasicAWSCredentials( 'AK' + 'I3P5V4A465MVY7N439', 'theseareinvalidcredentialsfVK1QwAGaRUDzE' ) ) )
        .withEndpointConfiguration( new AwsClientBuilder.EndpointConfiguration( EC2_ENDPOINT, 'eucalyptus' ) )
        .build( )
      client.describeAvailabilityZones( )
    } catch ( AmazonServiceException e ) {
      print( "Expected error: ${e}" )
      assertThat( 'AuthFailure' == e.errorCode, "Expected error code AuthFailure, but was: ${e.errorCode}" )
    }
  }

  @Test
  void testIamInstanceProfileAssociationStubs( ) throws Exception {
    testInfo( "${this.getClass().simpleName}.testIamInstanceProfileAssociationStubs" );

    ec2.with{
      try {
        associateIamInstanceProfile( new AssociateIamInstanceProfileRequest(
            instanceId: 'i-00000000',
            iamInstanceProfile: new IamInstanceProfileSpecification(
                name: 'my-instance-profile'
            )
        ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidInstanceID.NotFound' == e.errorCode, "Expected error code InvalidInstanceID.NotFound, but was: ${e.errorCode}" )
      }

      describeIamInstanceProfileAssociations( new DescribeIamInstanceProfileAssociationsRequest(
          associationIds: [
              'iip-assoc-08049da59357d598c'
          ],
          nextToken: 'invalid-token',
          maxResults: 100,
          filters: [
              new Filter( name: 'instance-id', values: [ 'i-00000000' ] )
          ]
      ) )

      try {
        disassociateIamInstanceProfile( new DisassociateIamInstanceProfileRequest(
            associationId: 'iip-assoc-08049da59357d598c'
        ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidParameterValue' == e.errorCode, "Expected error code InvalidParameterValue, but was: ${e.errorCode}" )
      }

      try {
        replaceIamInstanceProfileAssociation( new ReplaceIamInstanceProfileAssociationRequest(
            associationId: 'iip-assoc-08049da59357d598c',
            iamInstanceProfile: new IamInstanceProfileSpecification(
                name: 'my-instance-profile'
            )
        ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidParameterValue' == e.errorCode, "Expected error code InvalidParameterValue, but was: ${e.errorCode}" )
      }

      void
    }
  }

  @Test
  void testIpv6Stubs( ) throws Exception {
    testInfo( "${this.getClass().simpleName}.testIpv6Stubs" );

    ec2.with{
      try {
        assignIpv6Addresses( new AssignIpv6AddressesRequest(
            networkInterfaceId: 'eni-00000000',
            ipv6Addresses: [
                '2001:db8:1234:1a00::123',
                '2001:db8:1234:1a00::456'
            ]
        ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidNetworkInterfaceID.NotFound' == e.errorCode, "Expected error code InvalidNetworkInterfaceID.NotFound, but was: ${e.errorCode}" )
      }

      try {
        assignIpv6Addresses( new AssignIpv6AddressesRequest(
            networkInterfaceId: 'eni-00000000',
            ipv6AddressCount: 1
        ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidNetworkInterfaceID.NotFound' == e.errorCode, "Expected error code InvalidNetworkInterfaceID.NotFound, but was: ${e.errorCode}" )
      }

      try {
        associateSubnetCidrBlock( new AssociateSubnetCidrBlockRequest(
            subnetId: 'subnet-00000000',
            ipv6CidrBlock: '2001:db8:1234:1a00::/64'
        ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidSubnetID.NotFound' == e.errorCode, "Expected error code InvalidSubnetID.NotFound, but was: ${e.errorCode}" )
      }

      try {
        associateVpcCidrBlock( new AssociateVpcCidrBlockRequest(
            vpcId: 'vpc-00000000',
            amazonProvidedIpv6CidrBlock: true
        ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidVpcID.NotFound' == e.errorCode, "Expected error code InvalidVpcID.NotFound, but was: ${e.errorCode}" )
      }

      try {
        createEgressOnlyInternetGateway( new CreateEgressOnlyInternetGatewayRequest(
            vpcId: 'vpc-00000000',
            // clientToken: UUID.randomUUID( ).toString( ) // error on aws/ec2: ClientToken is not recognized
        ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidVpcID.NotFound' == e.errorCode, "Expected error code InvalidVpcID.NotFound, but was: ${e.errorCode}" )
      }

      try {
        deleteEgressOnlyInternetGateway( new DeleteEgressOnlyInternetGatewayRequest(
            egressOnlyInternetGatewayId: 'eigw-00000000000000000'
        ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidGatewayID.NotFound' == e.errorCode, "Expected error code InvalidGatewayID.NotFound, but was: ${e.errorCode}" )
      }

      try {
        describeEgressOnlyInternetGateways( new DescribeEgressOnlyInternetGatewaysRequest(
            egressOnlyInternetGatewayIds: [
              'eigw-00000000000000000'
            ],
            maxResults: 100,
            nextToken: 'invalid-next-token'
        ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidNextToken' == e.errorCode, "Expected error code InvalidNextToken, but was: ${e.errorCode}" )
      }

      try {
        disassociateSubnetCidrBlock( new DisassociateSubnetCidrBlockRequest(
            associationId: 'subnet-cidr-assoc-00000000'
        ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidSubnetCidrBlockAssociationID.NotFound' == e.errorCode, "Expected error code InvalidSubnetCidrBlockAssociationID.NotFound, but was: ${e.errorCode}" )
      }

      try {
        disassociateVpcCidrBlock( new DisassociateVpcCidrBlockRequest(
            associationId: 'vpc-cidr-assoc-00000000'
        ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidVpcCidrBlockAssociationID.NotFound' == e.errorCode, "Expected error code InvalidVpcCidrBlockAssociationID.NotFound, but was: ${e.errorCode}" )
      }

      try {
        unassignIpv6Addresses( new UnassignIpv6AddressesRequest(
            networkInterfaceId: 'eni-00000000',
            ipv6Addresses: [
                '2001:db8:1234:1a00::123',
                '2001:db8:1234:1a00::456'
            ]
        ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidNetworkInterfaceID.NotFound' == e.errorCode, "Expected error code InvalidNetworkInterfaceID.NotFound, but was: ${e.errorCode}" )
      }

      void
    }
  }

  @Test
  void testScheduledInstanceStubs( ) throws Exception {
    testInfo( "${this.getClass().simpleName}.testScheduledInstanceStubs" );

    ec2.with{
      try {
        print( 'Describing scheduled instance availability')
        print( describeScheduledInstanceAvailability( new DescribeScheduledInstanceAvailabilityRequest(
            recurrence: new ScheduledInstanceRecurrenceRequest(
                frequency: 'Monthly',
                interval: 1,
                occurrenceDays: [1, 3, 5, 7],
                occurrenceRelativeToEnd: false,
                occurrenceUnit: 'DayOfMonth'
            ),
            firstSlotStartTimeRange: new SlotDateTimeRangeRequest(
                earliestTime: new Date( System.currentTimeMillis( ) + TimeUnit.HOURS.toMillis( 6 ) ),
                latestTime: new Date( System.currentTimeMillis( ) + TimeUnit.HOURS.toMillis( 12 ) )
            ),
            minSlotDurationInHours: 1,
            maxSlotDurationInHours: 24,
            nextToken: 'invalid-token',
            maxResults: 100,
            filters: [
                new Filter( name: 'network-platform', values: [ 'EC2-VPC' ] )
            ]
        ) ).toString( ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidPaginationToken' == e.errorCode, "Expected error code InvalidPaginationToken, but was: ${e.errorCode}" )
      }

      try {
        print( 'Describing scheduled instances')
        print( describeScheduledInstances( new DescribeScheduledInstancesRequest(
            scheduledInstanceIds: [ 'sci-00000000000000000' ],
            slotStartTimeRange: new SlotStartTimeRangeRequest(
                earliestTime: new Date( ),
                latestTime: new Date( System.currentTimeMillis( ) + TimeUnit.DAYS.toMillis( 365 ) )
            ),
            nextToken: 'invalid-token',
            maxResults: 100,
            filters: [
                new Filter( name: 'a', values: [ 'b' ] )
            ]
        ) ).toString( ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidParameterValue' == e.errorCode, "Expected error code InvalidParameterValue, but was: ${e.errorCode}" )
      }

      try {
        purchaseScheduledInstances( new PurchaseScheduledInstancesRequest(
            clientToken: UUID.randomUUID( ).toString( ),
            purchaseRequests: [
                new PurchaseRequest(
                    purchaseToken: 'dGhpcyBpcyBub3QgYSB2YWxpZCB0b2tlbgo=',
                    instanceCount: 1
                )
            ]
        ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidPurchaseToken.Malformed' == e.errorCode, "Expected error code InvalidPurchaseToken.Malformed, but was: ${e.errorCode}" )
      }

      try {
        runScheduledInstances( new RunScheduledInstancesRequest(
            clientToken: UUID.randomUUID( ).toString( ),
            instanceCount: 1,
            scheduledInstanceId: 'sci-00000000000000000',
            launchSpecification: new ScheduledInstancesLaunchSpecification(
                imageId: 'emi-00000000',
                subnetId: 'subnet-00000000',
                keyName: 'my-key',
                securityGroupIds: [ 'sg-00000000' ]
            )
        ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidScheduledInstance' == e.errorCode, "Expected error code InvalidScheduledInstance, but was: ${e.errorCode}" )
      }

      void
    }
  }

  @Test
  void testHostsStubs( ) throws Exception {
    testInfo( "${this.getClass().simpleName}.testHostsStubs" );

    ec2.with{
      try {
        allocateHosts( new AllocateHostsRequest(
            autoPlacement: 'off',
            availabilityZone: 'some-zone',
            clientToken: UUID.randomUUID( ).toString( ),
            instanceType: 'm1.small',
            quantity: 1
        ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidRequest' == e.errorCode, "Expected error code InvalidRequest, but was: ${e.errorCode}" )
      }

      try {
        print( 'Describing host reservation offering')
        print( describeHostReservationOfferings( new DescribeHostReservationOfferingsRequest(
            offeringId: 'hro-00000000',
            minDuration: 1,
            maxDuration: 1,
            filter: [
                new Filter( name: 'a', values: [ 'b' ] )
            ]
        ) ).toString( ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidHostReservationOfferingId.NotFound' == e.errorCode, "Expected error code InvalidHostReservationOfferingId.NotFound, but was: ${e.errorCode}" )
      }

      try {
        print( 'Describing host reservations')
        print( describeHostReservations( new DescribeHostReservationsRequest(
            hostReservationIdSet: [ 'hr-00000000' ],
            filter: [
                new Filter( name: 'a', values: [ 'b' ] )
            ]
        ) ).toString( ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidHostReservationId.NotFound' == e.errorCode, "Expected error code InvalidHostReservationId.NotFound, but was: ${e.errorCode}" )
      }

      try {
        print( 'Describing hosts')
        print( describeHosts( new DescribeHostsRequest(
            hostIds: [ 'h-00000000' ],
            filter: [
                new Filter( name: 'a', values: [ 'b' ] )
            ]
        ) ).toString( ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidHostID.NotFound' == e.errorCode, "Expected error code InvalidHostID.NotFound, but was: ${e.errorCode}" )
      }

      try {
        getHostReservationPurchasePreview( new GetHostReservationPurchasePreviewRequest(
            offeringId: 'hro-00000000',
            hostIdSet: [ 'h-00000000' ]
        ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidHostReservationOfferingId.NotFound' == e.errorCode, "Expected error code InvalidHostReservationOfferingId.NotFound, but was: ${e.errorCode}" )
      }

      print( 'Modifying hosts')
      print( modifyHosts( new ModifyHostsRequest(
          autoPlacement: 'off',
          hostIds: [ 'h-00000000' ]
      ) ).toString( ) )

      try {
        purchaseHostReservation( new PurchaseHostReservationRequest(
            offeringId: 'hro-00000000',
            hostIdSet: [ 'h-00000000' ],
            limitPrice: '1.00',
            currencyCode: 'USD',
            clientToken: UUID.randomUUID( ).toString( )
        ) )
      } catch ( AmazonServiceException e ) {
        print( "Expected error: ${e}" )
        assertThat( 'InvalidParameter' == e.errorCode, "Expected error code InvalidParameter, but was: ${e.errorCode}" )

      }

      print( 'Releasing hosts')
      print( releaseHosts( new ReleaseHostsRequest(
          hostIds: [ 'h-00000000' ]
      ) ).toString( ) )

      void
    }
  }
}
