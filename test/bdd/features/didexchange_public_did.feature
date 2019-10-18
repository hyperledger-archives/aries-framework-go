#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange

@all
Feature: Decentralized Identifier(DID) exchange between the agents using public did in invitation

  @didexchange_public_did
  Scenario: did exchange e2e flow using public DID in invitation
    Given "Maria" agent is running on "localhost" port "random" with http-binding did resolver url "http://localhost:48326/.sidetree/document" which accepts did method "sidetree"
    And   "Maria" registers to receive notification for post state event "completed"
    Given "Lisa" agent is running on "localhost" port "random" with http-binding did resolver url "http://localhost:48326/.sidetree/document" which accepts did method "sidetree"
    And   "Lisa" registers to receive notification for post state event "completed"
    And   "Maria" creates public DID using sidetree "http://localhost:48326/.sidetree/document"
    # we wait until observer polls sidetree txn
    Then  "Maria" waits for public did to become avaiable in sidetree for up to 5 seconds
    And   "Maria" creates invitation with public DID
    And   "Lisa" receives invitation from "Maria"
    And   "Maria" waits for post state event "completed"
    And   "Lisa" waits for post state event "completed"
    And   "Maria" retrieves connection record and validates that connection state is "completed"
    And   "Lisa" retrieves connection record and validates that connection state is "completed"