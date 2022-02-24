#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange

@all
@didexchange_e2e_sdk_didcommv2
Feature: Decentralized Identifier(DID) exchange between the agents using SDK with DIDComm V2 media type profile
  @localkms_didexchange_e2e_sdk_didcommv2
  Scenario Outline: did exchange e2e flow with DIDComm V2 media type profile
    Given options "<keyType>" "<keyAgreementType>" "<mediaTypeProfile>"
      And "Alice" agent is running on "localhost" port "random" with "http" using scenario media type profile as the transport provider
      And   "Alice" creates did exchange client
      And   "Alice" registers to receive notification for post state event "completed"

    Given "Bob" agent is running on "localhost" port "random" with "http" using scenario media type profile as the transport provider
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

    Examples:
      | keyType              | keyAgreementType | mediaTypeProfile |
      | "ECDSAP256IEEEP1363" | "X25519ECDHKW"   | "didcomm/v2"     |

  Scenario Outline: did exchange e2e flow using WebSocket as the DIDComm transport with DIDComm V2 media type profile
    Given options "<keyType>" "<keyAgreementType>" "<mediaTypeProfile>"
      And "Alice" agent is running on "localhost" port "random" with "websocket" using scenario media type profile as the transport provider
      And   "Alice" creates did exchange client
      And   "Alice" registers to receive notification for post state event "completed"

    When "Bob" agent is running on "localhost" port "random" with "websocket" using scenario media type profile as the transport provider
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

    Examples:
      | keyType              | keyAgreementType | mediaTypeProfile |
      | "ECDSAP256IEEEP1363" | "X25519ECDHKW"   | "didcomm/v2"     |
