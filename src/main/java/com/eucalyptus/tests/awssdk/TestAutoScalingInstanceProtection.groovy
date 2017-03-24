package com.eucalyptus.tests.awssdk

import com.amazonaws.services.autoscaling.model.CreateAutoScalingGroupRequest
import com.amazonaws.services.autoscaling.model.CreateLaunchConfigurationRequest
import com.amazonaws.services.autoscaling.model.DescribeAutoScalingGroupsRequest
import com.amazonaws.services.autoscaling.model.DescribeAutoScalingInstancesRequest
import com.amazonaws.services.autoscaling.model.SetDesiredCapacityRequest
import com.amazonaws.services.autoscaling.model.SetInstanceHealthRequest
import com.amazonaws.services.autoscaling.model.SetInstanceProtectionRequest
import com.amazonaws.services.autoscaling.model.TerminateInstanceInAutoScalingGroupRequest
import com.amazonaws.services.autoscaling.model.UpdateAutoScalingGroupRequest
import com.amazonaws.services.ec2.model.TerminateInstancesRequest
import org.testng.annotations.Test

import java.util.concurrent.TimeUnit

import static com.eucalyptus.tests.awssdk.N4j.AVAILABILITY_ZONE
import static com.eucalyptus.tests.awssdk.N4j.IMAGE_ID
import static com.eucalyptus.tests.awssdk.N4j.INSTANCE_TYPE
import static com.eucalyptus.tests.awssdk.N4j.NAME_PREFIX
import static com.eucalyptus.tests.awssdk.N4j.assertThat
import static com.eucalyptus.tests.awssdk.N4j.deleteAutoScalingGroup
import static com.eucalyptus.tests.awssdk.N4j.deleteLaunchConfig
import static com.eucalyptus.tests.awssdk.N4j.as as auto
import static com.eucalyptus.tests.awssdk.N4j.ec2
import static com.eucalyptus.tests.awssdk.N4j.getCloudInfo
import static com.eucalyptus.tests.awssdk.N4j.getInstancesForGroup
import static com.eucalyptus.tests.awssdk.N4j.print
import static com.eucalyptus.tests.awssdk.N4j.sleep
import static com.eucalyptus.tests.awssdk.N4j.testInfo
import static com.eucalyptus.tests.awssdk.N4j.waitForInstances

/**
 * Test management of instance protection settings and termination of protected instance.
 *
 * This is verification for the story:
 *
 * https://eucalyptus.atlassian.net/browse/EUCA-11860
 */
class TestAutoScalingInstanceProtection {

  @SuppressWarnings("unchecked")
  @Test
  void testAutoScalingInstanceProtection( ) {
    testInfo( this.getClass().simpleName )
    getCloudInfo( )
    final List<Runnable> cleanupTasks = new ArrayList<Runnable>()
    try {
      // Create launch configuration
      final String configName = "${NAME_PREFIX}InstanceProtectionTest"
      print( "Creating launch configuration: ${configName}" )
      auto.createLaunchConfiguration( new CreateLaunchConfigurationRequest(
          launchConfigurationName: configName,
          imageId: IMAGE_ID,
          instanceType: INSTANCE_TYPE
      ) )
      cleanupTasks.add{
        print( "Deleting launch configuration: ${configName}" )
        deleteLaunchConfig(configName)
      }

      // Create scaling group
      final String groupName = "${NAME_PREFIX}InstanceProtectionTest"
      print( "Creating auto scaling group: ${groupName}" )
      auto.createAutoScalingGroup( new CreateAutoScalingGroupRequest(
          autoScalingGroupName: groupName,
          launchConfigurationName: configName,
          desiredCapacity: 1,
          minSize: 0,
          maxSize: 1,
          newInstancesProtectedFromScaleIn: true,
          healthCheckType: "EC2",
          healthCheckGracePeriod: 600, // 10 minutes
          availabilityZones: [ AVAILABILITY_ZONE ]
      ) )
      cleanupTasks.add{
        print( "Deleting group: ${groupName}" )
        deleteAutoScalingGroup(groupName,true)
      }
      cleanupTasks.add( new Runnable() {
        @Override
        public void run() {
          final List<String> instanceIds = (List<String>) getInstancesForGroup(groupName, null,true )
          print( "Terminating instances: ${instanceIds}" )
          ec2.terminateInstances( new TerminateInstancesRequest().withInstanceIds( instanceIds ) )
        }
      } )

      // Check group protection setting
      print( "Describing group to check instance protection" )
      auto.describeAutoScalingGroups( new DescribeAutoScalingGroupsRequest(
          autoScalingGroupNames: [ groupName ]
      ) ).with {
        assertThat( autoScalingGroups != null, 'Expected auto scaling groups' )
        assertThat( autoScalingGroups.size() == 1,
            "Expected 1 auto scaling group, but was: ${autoScalingGroups.size()}" )
        assertThat( autoScalingGroups[0].newInstancesProtectedFromScaleIn,
            "Expected new instances protected" )
      }

      // Wait for instances to launch
      print( "Waiting for instance to launch" )
      final long timeout = TimeUnit.MINUTES.toMillis(5)
      String instanceId = (String) waitForInstances(timeout,1,groupName,true).get(0)

      // Ensure instance protected
      print( "Describing instance to check protected" )
      auto.describeAutoScalingInstances( new DescribeAutoScalingInstancesRequest(
        instanceIds: [ instanceId ]
      ) ).with {
        assertThat( autoScalingInstances != null, 'Expected auto scaling instances' )
        assertThat( autoScalingInstances.size() == 1,
            "Expected 1 auto scaling instance, but was: ${autoScalingInstances.size()}" )
        assertThat( autoScalingInstances[0].protectedFromScaleIn,
            "Expected instance protected from scale in" )
      }

      // Test changing settings for group
      print( "Testing changing protection for group ${groupName}" )
      [ false, true ].each { protectedFromScaleIn ->
        print( "Setting new instance protection to ${protectedFromScaleIn}" )
        auto.updateAutoScalingGroup( new UpdateAutoScalingGroupRequest(
            autoScalingGroupName: groupName,
            newInstancesProtectedFromScaleIn: protectedFromScaleIn
        ) )
        auto.describeAutoScalingGroups( new DescribeAutoScalingGroupsRequest(
            autoScalingGroupNames: [ groupName ]
        ) ).with {
          assertThat( autoScalingGroups != null, 'Expected auto scaling groups' )
          assertThat( autoScalingGroups.size() == 1,
              "Expected 1 auto scaling group, but was: ${autoScalingGroups.size()}" )
          autoScalingGroups[0].with {
            assertThat( newInstancesProtectedFromScaleIn == protectedFromScaleIn,
                "Expected new instances protected ${protectedFromScaleIn}, but was ${newInstancesProtectedFromScaleIn}")
          }
        }
      }

      // Test changing settings for instance
      print( "Testing changing protection for instance ${instanceId}" )
      [ false, true ].each { protectedFromScaleIn ->
        print( "Setting protection to ${protectedFromScaleIn}" )
        auto.setInstanceProtection( new SetInstanceProtectionRequest(
            autoScalingGroupName: groupName,
            instanceIds: [ instanceId ],
            protectedFromScaleIn: protectedFromScaleIn
        ) )
        auto.describeAutoScalingInstances( new DescribeAutoScalingInstancesRequest(
            instanceIds: [ instanceId ]
        ) ).with {
          assertThat( autoScalingInstances != null, 'Expected auto scaling instances' )
          assertThat( autoScalingInstances.size() == 1,
              "Expected 1 auto scaling instance, but was: ${autoScalingInstances.size()}" )
          autoScalingInstances[0].with {
            assertThat( it.protectedFromScaleIn == protectedFromScaleIn,
                "Expected instance protection ${protectedFromScaleIn}, but was ${it.protectedFromScaleIn}" )
          }
        }
      }

      // Wait for instance to be in service so protection applies
      print ( "Waiting for instance to be in service ${instanceId}" )
      waitForInstances("InService", TimeUnit.MINUTES.toMillis(5), groupName, false);

      // Ensure scaling does not terminate it
      print( "Setting desired capacity to zero for group: ${groupName}" )
      auto.setDesiredCapacity( new SetDesiredCapacityRequest(
          autoScalingGroupName: groupName,
          desiredCapacity: 0
      ) )

      // Wait for instances to terminate
      print( 'Waiting a minute to ensure instance not terminated.' )
      sleep( 60 )
      auto.describeAutoScalingInstances( new DescribeAutoScalingInstancesRequest(
          instanceIds: [ instanceId ]
      ) ).with {
        assertThat(autoScalingInstances != null, 'Expected auto scaling instances')
        assertThat(autoScalingInstances.size() == 1,
            "Expected 1 auto scaling instance, but was: ${autoScalingInstances.size()}")
      }

      // Reset desired capacity for unhealthy instance replacement testing
      print( "Setting desired capacity to 1 for group: ${groupName}" )
      auto.setDesiredCapacity( new SetDesiredCapacityRequest(
          autoScalingGroupName: groupName,
          desiredCapacity: 1
      ) )

      // Ensure unhealthy protected instance is replaced
      print( "Marking protected instance as unhealthy to ensure replaced ${instanceId}" )
      auto.setInstanceHealth( new SetInstanceHealthRequest(
          instanceId: instanceId,
          healthStatus: 'Unhealthy',
          shouldRespectGracePeriod: false
      ) )
      String instanceId2 = (String) waitForInstances(timeout,1,groupName,true,[instanceId]).get(0)
      waitForInstances("InService", TimeUnit.MINUTES.toMillis(5), groupName, false);

      // Ensure manual termination works
      print( "Terminating instance in group: ${instanceId2}" )
      auto.terminateInstanceInAutoScalingGroup( new TerminateInstanceInAutoScalingGroupRequest(
          instanceId: instanceId2,
          shouldDecrementDesiredCapacity: true
      ))

      // Wait for instances to terminate
      print( 'Waiting for instance to terminate' )
      waitForInstances(timeout,0,groupName,true)

      print( 'Test complete' )
    } finally {
      // Attempt to clean up anything we created
      Collections.reverse( cleanupTasks )
      for ( final Runnable cleanupTask : cleanupTasks ) {
        try {
          cleanupTask.run()
        } catch ( Exception e ) {
          e.printStackTrace()
        }
      }
    }
  }

}
