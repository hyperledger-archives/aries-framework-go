#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@controller
@messaging_e2e_controller
Feature: Messaging between the agents using REST/controller binding

  # Reference : https://github.com/hyperledger/aries-rfcs/blob/master/features/0351-purpose-decorator/README.md
  Scenario: sending message from one agent to another using message service
    Given "Baha" agent is running on "localhost" port "8081" with webhook "http://localhost:8083" and controller "https://localhost:8082"
    And   "Baha" registers a message service through controller with name "generic-invite" for type "https://didcomm.org/generic/1.0/message" and purpose "meeting,appointment,event"

    Given "Tal" agent is running on "localhost" port "9081" with webhook "http://localhost:9083" and controller "https://localhost:9082"
    And   "Tal" registers a message service through controller with name "generic-invite-response" for type "https://didcomm.org/generic/1.0/message" and purpose "invite-response"

    Given "Baha" has established connection with "Tal" through did exchange using controller
    And   "Tal" saves the connectionID to variable "Tal"

    When  "Tal" sends meeting invite message "Hey, meet me today at 4PM" through controller with type "https://didcomm.org/generic/1.0/message" and purpose "meeting" to "Baha"
    Then  "Baha" receives invite message "Hey, meet me today at 4PM" with type "https://didcomm.org/generic/1.0/message" to webhook for topic "generic-invite" from "Tal"
    When  "Baha" replies to "Tal" with message "Sure, see you there !!" through controller with type "https://didcomm.org/generic/1.0/message" and purpose "invite-response"
    Then  "Tal" receives invite message "Sure, see you there !!" with type "https://didcomm.org/generic/1.0/message" to webhook for topic "generic-invite-response" from "Baha"

  @basic_message_e2e_controller
    # Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0095-basic-message
  Scenario: sending message from one agent to another using message service controller through "Basic Message Protocol 1.0"
    Given "Baha" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And   "Baha" registers a message service through controller with name "basic-message" for basic message type

    Given "Tal" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
    And   "Baha" has established connection with "Tal" through did exchange using controller
    And   "Tal" saves the connectionID to variable "Tal"

    When  "Tal" sends basic message "Your hovercraft is full of eels." through controller to "Baha"
    Then   "Baha" receives basic message "Your hovercraft is full of eels." for topic "basic-message" from "Tal"

  # Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0095-basic-message
  Scenario: sending out of band message from one agent to another using message service controller through "Basic Message Protocol 1.0"
    Given "Baha" agent is running on "localhost" port "8081" with controller "https://localhost:8082" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    And   "Baha" registers a message service through controller with name "basic-message" for basic message type
    And   "Baha" creates "sidetree" public DID through controller

    Given "Tal" agent is running on "localhost" port "9081" with controller "https://localhost:9082" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"

    When  "Tal" sends out of band basic message "Your hovercraft is full of eels, careful !!" through controller to "Baha"
    Then  "Baha" receives basic message "Your hovercraft is full of eels, careful !!" for topic "basic-message" from "Tal"