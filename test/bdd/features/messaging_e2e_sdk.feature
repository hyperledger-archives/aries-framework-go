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

    Given   "Filip" registers a message service with name "generic-invite" for type "https://didcomm.org/generic/1.0/message" and purpose "meeting,appointment,event"
      And   "Filip" creates did exchange client

    Given "Derek" agent is running on "localhost" port "random" with "http" as the transport provider
      And   "Derek" creates did exchange client

    Given "Filip" has established connection with "Derek" through did exchange

    When   "Derek" sends meeting invite message "Hey, meet me today at 4PM" with type "https://didcomm.org/generic/1.0/message" and purpose "meeting" to "Filip"
    Then   "Filip" message service receives meeting invite message "Hey, meet me today at 4PM" with type "https://didcomm.org/generic/1.0/message" from "Derek"

  @basic_message_e2e_sdk
    # Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0095-basic-message
  Scenario: sending message from one agent to another using message service using "Basic Message Protocol 1.0"
    Given "Filip" agent with message registrar is running on "localhost" port "random" with "http" as the transport provider

    Given   "Filip" registers a message service with name "basic-message" for basic message type
    And   "Filip" creates did exchange client

    Given "Derek" agent is running on "localhost" port "random" with "http" as the transport provider
    And   "Derek" creates did exchange client

    Given "Filip" has established connection with "Derek" through did exchange

    When   "Derek" sends basic message "Your hovercraft is full of eels." to "Filip"
    Then   "Filip" receives basic message "Your hovercraft is full of eels." from "Derek"

    # Reference : https://github.com/hyperledger/aries-rfcs/blob/master/features/0351-purpose-decorator/README.md
  Scenario: sending out of band message from one agent to another using message service without didexchange
    Given "Tom" agent with message registrar is running on "localhost" port "random" with "http" as the transport provider and http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"

    Given "Tom" registers a message service with name "generic-invite" for type "https://didcomm.org/generic/1.0/message" and purpose "meeting,appointment,event"
    And   "Tom" creates public DID for did method "sidetree"
    And   "Tom" waits for public did to become available in sidetree for up to 10 seconds

    Given "Aleks" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"

    When   "Aleks" sends out of band meeting invite message "Hey, meet me today at 4PM" with type "https://didcomm.org/generic/1.0/message" and purpose "meeting" to "Tom"
    Then   "Tom" message service receives meeting invite message "Hey, meet me today at 4PM" with type "https://didcomm.org/generic/1.0/message" from "Aleks"
