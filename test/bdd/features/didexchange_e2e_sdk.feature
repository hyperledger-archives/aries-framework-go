#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange

@all
@didexchange_e2e_sdk
Feature: Decentralized Identifier(DID) exchange between the agents using SDK
  @localkms_didexchange_e2e_sdk
  Scenario: did exchange e2e flow
    Given "Alice" is started with a "http" DIDComm endpoint
      And   "Alice" creates did exchange client
      And   "Alice" registers to receive notification for post state event "completed"

    Given "Bob" is started with a "http" DIDComm endpoint
      And   "Bob" creates did exchange client

    When   "Bob" registers to receive notification for post state event "completed"
      And   "Alice" creates invitation
      And   "Bob" receives invitation from "Alice"
      And   "Bob" approves invitation request
      And   "Alice" approves did exchange request
      And   "Alice" waits for post state event "completed"
      And   "Bob" waits for post state event "completed"

    Then   "Alice" retrieves connection record and validates that connection state is "completed"
      And   "Bob" retrieves connection record and validates that connection state is "completed"

  Scenario: did exchange e2e flow using WebSocket as the DIDComm transport
    Given "Alice" is started with a "websocket" DIDComm endpoint
      And   "Alice" creates did exchange client
      And   "Alice" registers to receive notification for post state event "completed"

    When "Bob" is started with a "websocket" DIDComm endpoint
      And   "Bob" creates did exchange client
      And   "Bob" registers to receive notification for post state event "completed"
      And   "Alice" creates invitation
      And   "Bob" receives invitation from "Alice"
      And   "Bob" approves invitation request
      And   "Alice" approves did exchange request
      And   "Alice" waits for post state event "completed"
      And   "Bob" waits for post state event "completed"

    Then   "Alice" retrieves connection record and validates that connection state is "completed"
      And   "Bob" retrieves connection record and validates that connection state is "completed"

  @webkms_didexchange_e2e_sdk
  Scenario: did exchange e2e flow with agents using webkms
    Given "Sudesh" uses webkms with key server at "https://localhost:8076", using "did:key:dummy-sample:sudesh" controller
      And "Sudesh" is started with a "http" DIDComm endpoint

    And   "Sudesh" creates did exchange client
    And   "Sudesh" registers to receive notification for post state event "completed"

    Given "Firas" uses webkms with key server at "https://localhost:8076", using "did:key:dummy-sample:firas" controller
      And "Firas" is started with a "http" DIDComm endpoint

    And   "Firas" creates did exchange client
    And   "Firas" registers to receive notification for post state event "completed"

    When  "Sudesh" creates invitation
    And   "Firas" receives invitation from "Sudesh"
    And   "Firas" approves invitation request
    And   "Sudesh" approves did exchange request
    And   "Sudesh" waits for post state event "completed"
    And   "Firas" waits for post state event "completed"

    Then   "Sudesh" retrieves connection record and validates that connection state is "completed"
    And   "Firas" retrieves connection record and validates that connection state is "completed"
