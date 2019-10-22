#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange

@all
Feature: Decentralized Identifier(DID) exchange between the agents using controller API

  @didexchange_e2e_controller
  Scenario: did exchange e2e flow using controller api
    Given "Alice" agent is running on "localhost" port "${ALICE_AGENT_PORT}" with controller "${ALICE_CONTROLLER_URL}" and webhook "${ALICE_WEBHOOK_URL}"
    And "Bob" agent is running on "localhost" port "${BOB_AGENT_PORT}" with controller "${BOB_CONTROLLER_URL}" and webhook "${BOB_WEBHOOK_URL}"
    And   "Alice" creates invitation through controller
    And   "Bob" receives invitation from "Alice" through controller
    And   "Alice" waits for post state event "completed" to webhook
    And   "Bob" waits for post state event "completed" to webhook
    And   "Alice" retrieves connection record through controller and validates that connection state is "completed"
    And   "Bob" retrieves connection record through controller and validates that connection state is "completed"

