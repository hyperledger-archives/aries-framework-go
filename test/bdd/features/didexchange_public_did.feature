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
  Scenario Outline: did exchange e2e flow using public DID in invitation
    Given options "<keyType>" "<keyAgreementType>" "<mediaTypeProfile>"

    Given "Maria" uses http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
      And "Maria" uses configured encryption parameters
      And "Maria" is started with a "http" DIDComm endpoint
      And "Maria" creates public DID for did method "sidetree"
    # we wait until observer polls sidetree txn
     Then "Maria" waits for public did to become available in sidetree for up to 10 seconds
      And "Maria" creates did exchange client
      And "Maria" registers to receive notification for post state event "completed"

    Given "Lisa" uses http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
      And "Lisa" uses configured encryption parameters
      And "Lisa" is started with a "http" DIDComm endpoint
      And "Lisa" creates public DID for did method "sidetree"
    # we wait until observer polls sidetree txn
     Then "Lisa" waits for public did to become available in sidetree for up to 10 seconds
      And "Lisa" creates did exchange client
      And "Lisa" registers to receive notification for post state event "completed"
      And "Maria" creates invitation with public DID
      And "Lisa" receives invitation from "Maria"
      And "Lisa" approves invitation request
      And "Maria" approves did exchange request
      And "Maria" waits for post state event "completed"
      And "Lisa" waits for post state event "completed"

     Then "Maria" retrieves connection record and validates that connection state is "completed"
      And "Lisa" retrieves connection record and validates that connection state is "completed"
    Examples:
      | keyType    | keyAgreementType   | mediaTypeProfile          |
      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip1"            |
      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip2;env=rfc19"  |
      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip2;env=rfc587" |
      | "ED25519"  | "NISTP384ECDHKW"   | "didcomm/v2"              |

  @didexchange_sdk_mixed_public_and_peer_dids
  Scenario Outline: did exchange e2e flow using public DID in invitation
    Given options "<keyType>" "<keyAgreementType>" "<mediaTypeProfile>"
      And   "Julia" uses http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
      And   "Julia" uses configured encryption parameters
      And   "Julia" is started with a "http" DIDComm endpoint
      And   "Julia" creates public DID for did method "sidetree"
    # we wait until observer polls sidetree txn
    Then  "Julia" waits for public did to become available in sidetree for up to 10 seconds
      And   "Julia" creates did exchange client
      And   "Julia" registers to receive notification for post state event "completed"

    Given   "Kate" uses http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
      And   "Kate" uses configured encryption parameters
      And   "Kate" is started with a "http" DIDComm endpoint
      And   "Kate" creates did exchange client
      And   "Kate" registers to receive notification for post state event "completed"
      And   "Julia" creates invitation with public DID
      And   "Kate" receives invitation from "Julia"
      And   "Kate" approves invitation request
      And   "Julia" approves did exchange request
      And   "Julia" waits for post state event "completed"
      And   "Kate" waits for post state event "completed"

    Then   "Julia" retrieves connection record and validates that connection state is "completed"
      And   "Kate" retrieves connection record and validates that connection state is "completed"
    Examples:
      | keyType    | keyAgreementType   | mediaTypeProfile          |
      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip1"            |
      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip2;env=rfc19"  |
      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip2;env=rfc587" |
      | "ED25519"  | "NISTP384ECDHKW"   | "didcomm/v2"              |

  @didexchange_sdk_implicit_invitation_peer_did
  Scenario Outline: did exchange e2e flow using implicit invitation with public DID
    Given options "<keyType>" "<keyAgreementType>" "<mediaTypeProfile>"
      And "Maja" uses http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
      And "Maja" uses configured encryption parameters
      And "Maja" is started with a "http" DIDComm endpoint
      And "Maja" creates public DID for did method "sidetree"
    # we wait until observer polls sidetree txn
    Then  "Maja" waits for public did to become available in sidetree for up to 10 seconds
      And   "Maja" creates did exchange client
      And   "Maja" registers to receive notification for post state event "completed"

      And   "Filip" uses http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
      And   "Filip" uses configured encryption parameters
      And   "Filip" is started with a "http" DIDComm endpoint
      And   "Filip" creates did exchange client
      And   "Filip" registers to receive notification for post state event "completed"
      And   "Filip" initiates connection with "Maja" using peer DID
      And   "Maja" approves did exchange request
      And   "Maja" waits for post state event "completed"
      And   "Filip" waits for post state event "completed"

    Then   "Maja" retrieves connection record and validates that connection state is "completed"
      And   "Filip" retrieves connection record and validates that connection state is "completed"
    Examples:
      | keyType    | keyAgreementType   | mediaTypeProfile          |
      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip1"            |
      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip2;env=rfc19"  |
      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip2;env=rfc587" |
      | "ED25519"  | "NISTP384ECDHKW"   | "didcomm/v2"              |

  @didexchange_sdk_implicit_invitation_public_did
  Scenario Outline: did exchange e2e flow using implicit invitation with public DID
    Given options "<keyType>" "<keyAgreementType>" "<mediaTypeProfile>"
      And   "Uma" uses http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
      And   "Uma" uses configured encryption parameters
      And   "Uma" is started with a "http" DIDComm endpoint
      And   "Uma" creates public DID for did method "sidetree"
    # we wait until observer polls sidetree txn
    Then  "Uma" waits for public did to become available in sidetree for up to 10 seconds
      And   "Uma" creates did exchange client
      And   "Uma" registers to receive notification for post state event "completed"

    Given   "John" uses http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
      And   "John" uses configured encryption parameters
      And   "John" is started with a "http" DIDComm endpoint
      And   "John" creates public DID for did method "sidetree"
    # we wait until observer polls sidetree txn
    Then  "John" waits for public did to become available in sidetree for up to 10 seconds
      And   "John" creates did exchange client
      And   "John" registers to receive notification for post state event "completed"
      And   "John" initiates connection with "Uma" using public DID
      And   "Uma" approves did exchange request
      And   "Uma" waits for post state event "completed"
      And   "John" waits for post state event "completed"

    Then   "Uma" retrieves connection record and validates that connection state is "completed"
      And   "John" retrieves connection record and validates that connection state is "completed"
    Examples:
      | keyType    | keyAgreementType   | mediaTypeProfile          |
      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip1"            |
      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip2;env=rfc19"  |
      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip2;env=rfc587" |
      | "ED25519"  | "NISTP384ECDHKW"   | "didcomm/v2"              |

  @controller
  @didexchange_controller_public_dids_invitation
  Scenario: did exchange e2e controller flow with public DID in invitation and invitee public DID
    Given  "Filip" agent is running on "localhost" port "8081" with controller "https://localhost:8082" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
      And  "Derek" agent is running on "localhost" port "9081" with controller "https://localhost:9082" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"

    Then "Filip" creates "sidetree" public DID through controller
      And  "Derek" creates "sidetree" public DID through controller
      And  "Filip" creates invitation through controller using public DID and label "filip-agent"
      And  "Derek" receives invitation from "Filip" through controller
      And  "Derek" approves exchange invitation with public DID through controller

    Then "Filip" creates "sidetree" public DID through controller
      And  "Filip" approves exchange request with public DID through controller
      And  "Filip" waits for post state event "completed" to web notifier
      And  "Derek" waits for post state event "completed" to web notifier

    Then  "Filip" retrieves connection record through controller and validates that connection state is "completed"
    And  "Derek" retrieves connection record through controller and validates that connection state is "completed"

  @controller
  @didexchange_controller_mixed_public_and_peer_dids
  Scenario: did exchange e2e controller flow using public DID in invitation
    Given  "Filip" agent is running on "localhost" port "8081" with controller "https://localhost:8082" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
      And  "Derek" agent is running on "localhost" port "9081" with controller "https://localhost:9082" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"

    Then "Filip" creates "sidetree" public DID through controller
      And  "Derek" creates "sidetree" public DID through controller
      And  "Filip" creates invitation through controller using public DID and label "filip-agent"
      And  "Derek" receives invitation from "Filip" through controller
      And  "Derek" approves exchange invitation with public DID through controller
      And  "Filip" approves exchange request through controller
      And  "Filip" waits for post state event "completed" to web notifier
      And  "Derek" waits for post state event "completed" to web notifier

    Then  "Filip" retrieves connection record through controller and validates that connection state is "completed"
      And  "Derek" retrieves connection record through controller and validates that connection state is "completed"

  @controller
  @didexchange_controller_implicit_invitation_peer_did
  Scenario: did exchange e2e controller flow with implicit invitation and invitee peer DID
    Given  "Filip" agent is running on "localhost" port "8081" with controller "https://localhost:8082" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
      And  "Derek" agent is running on "localhost" port "9081" with controller "https://localhost:9082" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"

    Then "Filip" creates "sidetree" public DID through controller
      And  "Derek" creates "sidetree" public DID through controller
      And  "Derek" initiates connection through controller with "Filip" using peer DID
      And  "Filip" approves exchange request with public DID through controller
      And  "Filip" waits for post state event "completed" to web notifier
      And  "Derek" waits for post state event "completed" to web notifier

    Then  "Filip" retrieves connection record through controller and validates that connection state is "completed"
      And  "Derek" retrieves connection record through controller and validates that connection state is "completed"

  @controller
  @didexchange_controller_implicit_invitation_public_did
  Scenario: did exchange e2e controller flow with implicit invitation and invitee public DID
    Given "Filip" agent is running on "localhost" port "8081" with controller "https://localhost:8082" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
      And "Derek" agent is running on "localhost" port "9081" with controller "https://localhost:9082" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"

    Then "Filip" creates "sidetree" public DID through controller
      And  "Derek" creates "sidetree" public DID through controller
      And  "Derek" initiates connection through controller with "Filip" using public DID
      And  "Filip" approves exchange request with public DID through controller
      And  "Filip" waits for post state event "completed" to web notifier
      And  "Derek" waits for post state event "completed" to web notifier

    Then  "Filip" retrieves connection record through controller and validates that connection state is "completed"
      And  "Derek" retrieves connection record through controller and validates that connection state is "completed"

