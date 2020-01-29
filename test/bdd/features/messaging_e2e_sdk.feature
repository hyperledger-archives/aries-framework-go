#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@messaging_e2e_sdk
Feature: Messaging between the agents using SDK

  # Reference : https://github.com/hyperledger/aries-rfcs/blob/master/features/0351-purpose-decorator/README.md
  Scenario: sending message from one agent to another using message service
    Given "Filip" agent with message registrar is running on "localhost" port "random" with "http" as the transport provider
    And   "Filip" registers a message service with name "generic-invite" for type "https://didcomm.org/generic/1.0/message" and purpose "meeting,appointment,event"
    And   "Filip" creates did exchange client
    Given "Derek" agent is running on "localhost" port "random" with "http" as the transport provider
    And   "Derek" creates did exchange client
    Given "Filip" has established connection with "Derek" through did exchange
    And   "Derek" sends meeting invite message "Hey, meet me today at 4PM" with type "https://didcomm.org/generic/1.0/message" and purpose "meeting" to "Filip"
    And   "Filip" message service receives meeting invite message "Hey, meet me today at 4PM" with type "https://didcomm.org/generic/1.0/message" from "Derek"

  @basic_message_e2e_sdk
    # Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0095-basic-message
  Scenario: sending message from one agent to another using message service using "Basic Message Protocol 1.0"
    Given "Filip" agent with message registrar is running on "localhost" port "random" with "http" as the transport provider
    And   "Filip" registers a message service with name "basic-message" for basic message type
    And   "Filip" creates did exchange client
    Given "Derek" agent is running on "localhost" port "random" with "http" as the transport provider
    And   "Derek" creates did exchange client
    Given "Filip" has established connection with "Derek" through did exchange
    And   "Derek" sends basic message "Your hovercraft is full of eels." to "Filip"
    And   "Filip" receives basic message "Your hovercraft is full of eels." from "Derek"