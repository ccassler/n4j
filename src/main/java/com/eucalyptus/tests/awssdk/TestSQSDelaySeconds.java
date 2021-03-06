package com.eucalyptus.tests.awssdk;

import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.model.CreateQueueRequest;
import com.amazonaws.services.sqs.model.ListQueuesResult;
import com.amazonaws.services.sqs.model.Message;
import com.amazonaws.services.sqs.model.ReceiveMessageRequest;
import com.amazonaws.services.sqs.model.ReceiveMessageResult;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import com.google.common.collect.Maps;
import com.google.common.collect.ImmutableMap;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Optional;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

import static com.eucalyptus.tests.awssdk.N4j.*;
import static com.eucalyptus.tests.awssdk.N4j.synchronizedDeleteAccount;

/**
 * Created by ethomas on 10/4/16.
 */
public class TestSQSDelaySeconds {

  private String account;
  private String otherAccount;

  private AmazonSQS accountSQSClient;
  private AmazonSQS otherAccountSQSClient;
  private int MAX_RECEIVE_MESSAGE_MAX_NUMBER_OF_MESSAGES;

  @BeforeClass
  public void init() throws Exception {
    print("### PRE SUITE SETUP - " + this.getClass().getSimpleName());

    try {
      getCloudInfoAndSqs();
      MAX_RECEIVE_MESSAGE_MAX_NUMBER_OF_MESSAGES = getLocalConfigInt("MAX_RECEIVE_MESSAGE_MAX_NUMBER_OF_MESSAGES");
      account = "sqs-account-ds-a-" + System.currentTimeMillis();
      synchronizedCreateAccount(account);
      accountSQSClient = getSqsClientWithNewAccount(account, "admin");
      otherAccount = "sqs-account-ds-b-" + System.currentTimeMillis();
      synchronizedCreateAccount(otherAccount);
      otherAccountSQSClient = getSqsClientWithNewAccount(otherAccount, "admin");
    } catch (Exception e) {
      try {
        teardown();
      } catch (Exception ie) {
      }
      throw e;
    }
  }

  @AfterClass
  public void teardown() throws Exception {
    print("### POST SUITE CLEANUP - " + this.getClass().getSimpleName());
    if (account != null) {
      if (accountSQSClient != null) {
        ListQueuesResult listQueuesResult = accountSQSClient.listQueues();
        if (listQueuesResult != null) {
          listQueuesResult.getQueueUrls().forEach(accountSQSClient::deleteQueue);
        }
      }
      synchronizedDeleteAccount(account);
    }
    if (otherAccount != null) {
      if (otherAccountSQSClient != null) {
        ListQueuesResult listQueuesResult = otherAccountSQSClient.listQueues();
        if (listQueuesResult != null) {
          listQueuesResult.getQueueUrls().forEach(otherAccountSQSClient::deleteQueue);
        }
      }
      synchronizedDeleteAccount(otherAccount);
    }
  }

  @Test
  @Parameters("concise")
  public void testMessageDelay(@Optional("false") boolean concise) throws Exception {
    testInfo(this.getClass().getSimpleName() + " - testMessageDelay");
    String queueName = "queue_name_message_delay";
    // send messages out with a bit of spacing between delays
    // give yourself a little error time (5 seconds may be too little?)
    int errorSecs = 5;
    int skewErrorSecs = 10; // number of seconds between client and server?
    int spacingSecs = 15;
    int totalTime = spacingSecs * 6;

    CreateQueueRequest createQueueRequest = new CreateQueueRequest();
    createQueueRequest.setQueueName(queueName);
    createQueueRequest.getAttributes().put("VisibilityTimeout", "0");
    createQueueRequest.getAttributes().put("DelaySeconds", String.valueOf(1 * spacingSecs));
    String queueUrl = accountSQSClient.createQueue(createQueueRequest).getQueueUrl();
    Map<String, Long> sendTimestampsLocal = Maps.newHashMap();
    Map<String, Integer> delaySecondsMap = Maps.newHashMap();

    String messageId1 = accountSQSClient.sendMessage(queueUrl, "mess1").getMessageId();
    sendTimestampsLocal.put(messageId1, System.currentTimeMillis() / 1000);
    delaySecondsMap.put(messageId1, 1 * spacingSecs);

    SendMessageRequest sendMessageRequest1 = new SendMessageRequest();
    sendMessageRequest1.setQueueUrl(queueUrl);
    sendMessageRequest1.setDelaySeconds(2 * spacingSecs);
    sendMessageRequest1.setMessageBody("mess2");
    String messageId2 = accountSQSClient.sendMessage(sendMessageRequest1).getMessageId();
    sendTimestampsLocal.put(messageId2, System.currentTimeMillis() / 1000);
    delaySecondsMap.put(messageId2, 2 * spacingSecs);

    if (!concise) {
      accountSQSClient.setQueueAttributes(queueUrl, ImmutableMap.of("DelaySeconds", String.valueOf(3 * spacingSecs)));
      String messageId3 = accountSQSClient.sendMessage(queueUrl, "mess3").getMessageId();
      sendTimestampsLocal.put(messageId3, System.currentTimeMillis() / 1000);
      delaySecondsMap.put(messageId3, 3 * spacingSecs);

      SendMessageRequest sendMessageRequest2 = new SendMessageRequest();
      sendMessageRequest2.setQueueUrl(queueUrl);
      sendMessageRequest2.setDelaySeconds(4 * spacingSecs);
      sendMessageRequest2.setMessageBody("mess4");
      String messageId4 = accountSQSClient.sendMessage(sendMessageRequest2).getMessageId();
      sendTimestampsLocal.put(messageId4, System.currentTimeMillis() / 1000);
      delaySecondsMap.put(messageId4, 4 * spacingSecs);
    }

    Map<String, Long> firstReceiveTimestampsLocal = Maps.newHashMap();
    Map<String, Message> messages = Maps.newHashMap();
    ReceiveMessageRequest receiveMessageRequest = new ReceiveMessageRequest();
    receiveMessageRequest.setAttributeNames(Collections.singleton("All"));
    receiveMessageRequest.setMaxNumberOfMessages(MAX_RECEIVE_MESSAGE_MAX_NUMBER_OF_MESSAGES);
    receiveMessageRequest.setQueueUrl(queueUrl);

    if (!concise) {
      for (int i=0; i < totalTime; i++) {
        ReceiveMessageResult receiveMessageResult = accountSQSClient.receiveMessage(receiveMessageRequest);
        if (receiveMessageResult != null && receiveMessageResult.getMessages() != null) {
          for (Message message: receiveMessageResult.getMessages()) {
            firstReceiveTimestampsLocal.putIfAbsent(message.getMessageId(), System.currentTimeMillis() / 1000);
            messages.put(message.getMessageId(), message);
          }
        }
        Thread.sleep(1000L);
      }
    } else {
      long loopStart = System.currentTimeMillis();
      while (firstReceiveTimestampsLocal.size() < 2 && System.currentTimeMillis() - loopStart < 120000L) {
        ReceiveMessageResult receiveMessageResult = accountSQSClient.receiveMessage(receiveMessageRequest);
        if (receiveMessageResult != null && receiveMessageResult.getMessages() != null) {
          for (Message message: receiveMessageResult.getMessages()) {
            firstReceiveTimestampsLocal.putIfAbsent(message.getMessageId(), System.currentTimeMillis() / 1000);
            messages.put(message.getMessageId(), message);
          }
        }
        Thread.sleep(1000L);
      }
      if (firstReceiveTimestampsLocal.size() < 2) {
        throw new InterruptedException("Timeout");
      }
    }

    for (String messageId: sendTimestampsLocal.keySet()) {
      
      assertThat(sendTimestampsLocal.containsKey(messageId), "we should have a sent timestamp");
      assertThat(firstReceiveTimestampsLocal.containsKey(messageId), "we should received the message");
      assertThat(messages.containsKey(messageId), "we should received the message");

      long localSendTime = sendTimestampsLocal.get(messageId);
      long localReceiveTime = firstReceiveTimestampsLocal.get(messageId);
      
      long remoteSendTime = Long.parseLong(messages.get(messageId).getAttributes().get("SentTimestamp"));
      long remoteReceiveTime = Long.parseLong(messages.get(messageId).getAttributes().get("ApproximateFirstReceiveTimestamp"));

      long delaySeconds = delaySecondsMap.get(messageId);
      long localDelaySeconds = Math.abs(localReceiveTime - localSendTime);
      long remoteDelaySeconds = Math.abs(remoteReceiveTime - remoteSendTime);
      
      assertThat(Math.abs(delaySeconds - localDelaySeconds) < errorSecs,
        "Message " + messageId + " should have received first message within range (local timestamps)");
      assertThat(Math.abs(delaySeconds - remoteDelaySeconds) < errorSecs,
        "Message " + messageId + " should have received first message within range (remote timestamps)");
      // measure skew
      assertThat(Math.abs(localSendTime - remoteSendTime) < skewErrorSecs,
        "Message " + messageId + " should have clock skew within range on send timestamp");
      assertThat(Math.abs(localReceiveTime - remoteReceiveTime) < skewErrorSecs,
        "Message " + messageId + " should have clock skew within range on receive timestamp");
      // measure skew error
      assertThat(
        Math.abs(Math.abs(localSendTime - remoteSendTime) - Math.abs(localReceiveTime - remoteReceiveTime)) < errorSecs,
        "Message " + messageId + " should have clock skew ranges near each other");
    }
  }
  private int getLocalConfigInt(String propertySuffixInCapsAndUnderscores) throws IOException {
    String propertyName = "services.simplequeue." + propertySuffixInCapsAndUnderscores.toLowerCase();
    return Integer.parseInt(getConfigProperty(LOCAL_EUCTL_FILE, propertyName));
  }

}
