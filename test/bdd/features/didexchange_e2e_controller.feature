#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange

@all
@controller
@didexchange_e2e_controller
Feature: Decentralized Identifier(DID) exchange between the agents using controller API

  Scenario: did exchange e2e flow using controller api
    Given "Alice" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
      And   "Bob" agent is running on "localhost" port "9081" with controller "https://localhost:9082"

    When   "Alice" creates invitation through controller with label "alice-agent"
      And   "Bob" receives invitation from "Alice" through controller
      And   "Bob" approves exchange invitation through controller
      And   "Alice" approves exchange request through controller
      And   "Alice" waits for post state event "completed" to web notifier
      And   "Bob" waits for post state event "completed" to web notifier

    Then   "Alice" retrieves connection record through controller and validates that connection state is "completed"
      And   "Bob" retrieves connection record through controller and validates that connection state is "completed"
