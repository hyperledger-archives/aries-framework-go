#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange

@all
Feature: Decentralized Identifier(DID) exchange between the agents using public did in invitation

  @didexchange_public_dids
  Scenario: did exchange e2e flow using public DID in invitation
    Given "Maria" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    And   "Maria" creates public DID using sidetree "${SIDETREE_URL}"
    # we wait until observer polls sidetree txn
    Then  "Maria" waits for public did to become available in sidetree for up to 10 seconds
    And   "Maria" creates did exchange client
    And   "Maria" registers to receive notification for post state event "completed"
    Given "Lisa" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    And   "Lisa" creates public DID using sidetree "${SIDETREE_URL}"
    # we wait until observer polls sidetree txn
    Then  "Lisa" waits for public did to become available in sidetree for up to 10 seconds
    And   "Lisa" creates did exchange client
    And   "Lisa" registers to receive notification for post state event "completed"
    And   "Maria" creates invitation with public DID
    And   "Lisa" receives invitation from "Maria"
    And   "Lisa" approves invitation request
    And   "Maria" approves did exchange request
    And   "Maria" waits for post state event "completed"
    And   "Lisa" waits for post state event "completed"
    And   "Maria" retrieves connection record and validates that connection state is "completed"
    And   "Lisa" retrieves connection record and validates that connection state is "completed"

  @didexchange_mixed_public_and_peer_dids
  Scenario: did exchange e2e flow using public DID in invitation
    Given "Julia" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    And   "Julia" creates public DID using sidetree "${SIDETREE_URL}"
    # we wait until observer polls sidetree txn
    Then  "Julia" waits for public did to become available in sidetree for up to 10 seconds
    And   "Julia" creates did exchange client
    And   "Julia" registers to receive notification for post state event "completed"
    Given "Kate" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    And   "Kate" creates did exchange client
    And   "Kate" registers to receive notification for post state event "completed"
    And   "Julia" creates invitation with public DID
    And   "Kate" receives invitation from "Julia"
    And   "Kate" approves invitation request
    And   "Julia" approves did exchange request
    And   "Julia" waits for post state event "completed"
    And   "Kate" waits for post state event "completed"
    And   "Julia" retrieves connection record and validates that connection state is "completed"
    And   "Kate" retrieves connection record and validates that connection state is "completed"