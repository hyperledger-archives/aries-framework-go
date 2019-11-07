#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange

@all
Feature: Decentralized Identifier(DID) exchange between the agents using SDK

  @didexchange_e2e_sdk
  Scenario: did exchange e2e flow
    Given "Alice" agent is running on "localhost" port "random"
    And   "Alice" creates did exchange client
    And   "Alice" registers to receive notification for post state event "completed"
    Given "Bob" agent is running on "localhost" port "random"
    And   "Bob" creates did exchange client
    And   "Bob" registers to receive notification for post state event "completed"
    And   "Alice" creates invitation
    And   "Bob" receives invitation from "Alice"
    And   "Bob" approves invitation request
    And   "Alice" approves did exchange request
    And   "Alice" waits for post state event "completed"
    And   "Bob" waits for post state event "completed"
    And   "Alice" retrieves connection record and validates that connection state is "completed"
    And   "Bob" retrieves connection record and validates that connection state is "completed"
