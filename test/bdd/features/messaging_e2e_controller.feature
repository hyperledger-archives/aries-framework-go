#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@messaging_e2e_controller
Feature: Messaging between the agents using REST/controller binding

  Scenario: sending message from one agent to another using message service
    Given "Baha" agent is running on "localhost" port "8081" with controller "http://localhost:8082" and webhook "http://localhost:8083"
    And   "Baha" registers a message service through controller with name "generic-invite" for type "https://didcomm.org/generic/1.0/message" and purpose "meeting,appointment,event"

    Given "Tal" agent is running on "localhost" port "9081" with controller "http://localhost:9082" and webhook "http://localhost:9083"
    And   "Baha" has established connection with "Tal" through did exchange using controller

    When  "Tal" sends meeting invite message "Hey, meet me today at 4PM" through controller with type "https://didcomm.org/generic/1.0/message" and purpose "meeting" to "Baha"
    And   "Baha" message service receives meeting invite message to webhook "Hey, meet me today at 4PM" with type "https://didcomm.org/generic/1.0/message" from "Tal"