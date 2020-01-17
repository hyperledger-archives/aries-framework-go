#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@messaging_e2e_sdk
Feature: Messaging between the agents using SDK

  Scenario: sending message from one agent to another using message service
    Given "Filip" agent with message registrar is running on "localhost" port "random" with "http" as the transport provider
    And   "Filip" registers a message service with name "generic-invite" for type "https://didcomm.org/generic/1.0/message" and purpose "meeting,appointment,event"
    And   "Filip" creates did exchange client
    Given "Derek" agent is running on "localhost" port "random" with "http" as the transport provider
    And   "Derek" creates did exchange client
    Given "Filip" has established connection with "Derek" through did exchange
    And   "Derek" sends meeting invite message "Hey, meet me today at 4PM" with type "https://didcomm.org/generic/1.0/message" and purpose "meeting" to "Filip"
    And   "Filip" message service receives meeting invite message "Hey, meet me today at 4PM" with type "https://didcomm.org/generic/1.0/message" from "Derek"