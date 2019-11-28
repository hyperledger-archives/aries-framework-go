#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange

@all
@didexchange_public_dids
Feature: Decentralized Identifier(DID) exchange between the agents using public did in invitation

  @didexchange_sdk_public_dids_invitation
  Scenario: did exchange e2e flow using public DID in invitation
    Given "Maria" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    And   "Maria" creates public DID for did method "sidetree"
    # we wait until observer polls sidetree txn
    Then  "Maria" waits for public did to become available in sidetree for up to 10 seconds
    And   "Maria" creates did exchange client
    And   "Maria" registers to receive notification for post state event "completed"
    Given "Lisa" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    And   "Lisa" creates public DID for did method "sidetree"
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

  @didexchange_sdk_mixed_public_and_peer_dids
  Scenario: did exchange e2e flow using public DID in invitation
    Given "Julia" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    And   "Julia" creates public DID for did method "sidetree"
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

  @didexchange_sdk_implicit_invitation_peer_did
  Scenario: did exchange e2e flow using implicit invitation with public DID
    Given "Maja" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    And   "Maja" creates public DID for did method "sidetree"
    # we wait until observer polls sidetree txn
    Then  "Maja" waits for public did to become available in sidetree for up to 10 seconds
    And   "Maja" creates did exchange client
    And   "Maja" registers to receive notification for post state event "completed"
    Given "Filip" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    And   "Filip" creates did exchange client
    And   "Filip" registers to receive notification for post state event "completed"
    And   "Filip" initiates connection with "Maja" using peer DID
    And   "Maja" approves did exchange request
    And   "Maja" waits for post state event "completed"
    And   "Filip" waits for post state event "completed"
    And   "Maja" retrieves connection record and validates that connection state is "completed"
    And   "Filip" retrieves connection record and validates that connection state is "completed"

  @didexchange_sdk_implicit_invitation_public_did
  Scenario: did exchange e2e flow using implicit invitation with public DID
    Given "Uma" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    And   "Uma" creates public DID for did method "sidetree"
    # we wait until observer polls sidetree txn
    Then  "Uma" waits for public did to become available in sidetree for up to 10 seconds
    And   "Uma" creates did exchange client
    And   "Uma" registers to receive notification for post state event "completed"
    Given "John" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    And   "John" creates public DID for did method "sidetree"
    # we wait until observer polls sidetree txn
    Then  "John" waits for public did to become available in sidetree for up to 10 seconds
    And   "John" creates did exchange client
    And   "John" registers to receive notification for post state event "completed"
    And   "John" initiates connection with "Uma" using public DID
    And   "Uma" approves did exchange request
    And   "Uma" waits for post state event "completed"
    And   "John" waits for post state event "completed"
    And   "Uma" retrieves connection record and validates that connection state is "completed"
    And   "John" retrieves connection record and validates that connection state is "completed"

  @didexchange_controller_public_dids_invitation
  Scenario: did exchange e2e flow using public DID in invitation
    Given "Filip" agent is running on "localhost" port "8081" with controller "http://localhost:8082" and webhook "http://localhost:8083" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    And  "Derek" agent is running on "localhost" port "9081" with controller "http://localhost:9082" and webhook "http://localhost:9083" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    Then "Filip" creates "sidetree" public DID through controller
    And  "Derek" creates "sidetree" public DID through controller
    And  "Filip" creates invitation through controller using public DID and label "filip-agent"
    And  "Derek" receives invitation from "Filip" through controller
    And  "Derek" approves exchange invitation with public DID through controller
    Then "Filip" creates "sidetree" public DID through controller
    And  "Filip" approves exchange request with public DID through controller
    And  "Filip" waits for post state event "completed" to webhook
    And  "Derek" waits for post state event "completed" to webhook
    And  "Filip" retrieves connection record through controller and validates that connection state is "completed"
    And  "Derek" retrieves connection record through controller and validates that connection state is "completed"

  @didexchange_controller_mixed_public_and_peer_dids
  Scenario: did exchange e2e flow using public DID in invitation
    Given "Filip" agent is running on "localhost" port "8081" with controller "http://localhost:8082" and webhook "http://localhost:8083" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    And  "Derek" agent is running on "localhost" port "9081" with controller "http://localhost:9082" and webhook "http://localhost:9083" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    Then "Filip" creates "sidetree" public DID through controller
    And  "Derek" creates "sidetree" public DID through controller
    And  "Filip" creates invitation through controller using public DID and label "filip-agent"
    And  "Derek" receives invitation from "Filip" through controller
    And  "Derek" approves exchange invitation with public DID through controller
    And  "Filip" approves exchange request through controller
    And  "Filip" waits for post state event "completed" to webhook
    And  "Derek" waits for post state event "completed" to webhook
    And  "Filip" retrieves connection record through controller and validates that connection state is "completed"
    And  "Derek" retrieves connection record through controller and validates that connection state is "completed"


