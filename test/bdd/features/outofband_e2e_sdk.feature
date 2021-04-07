#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

# Reference : https://github.com/hyperledger/aries-rfcs/blob/master/features/0434-outofband/README.md

@all
@outofband
@outofband_e2e_sdk
Feature: Out-Of-Band protocol (Go API)

  Background:
    Given "Alice" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
      And "Bob" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"

  Scenario: handshake_protocols: yes | requests~attach: no | existing_conn: no
    Given "Alice" creates an out-of-band invitation
     When "Alice" sends the invitation to "Bob" through an out-of-band channel
      And "Bob" accepts the invitation and connects with "Alice"
     Then "Alice" and "Bob" confirm their connection is "completed"

  Scenario: handshake_protocols: yes | requests~attach: yes | existing_conn: no
    Given "Alice" creates an out-of-band invitation with an attached offer-credential message
      And "Alice" sends the invitation to "Bob" through an out-of-band channel
      And "Bob" accepts the invitation and connects with "Alice"
     When "Bob" accepts the offer-credential message from "Alice"
     Then "Bob" is issued the credential

  Scenario: handshake_protocols: yes | requests~attach: no | existing_conn: yes
    Given "Alice" creates an out-of-band invitation with a public DID
      And "Bob" connects with "Alice" using the invitation
     When "Alice" creates another out-of-band invitation with the same public DID
      And "Alice" sends the invitation to "Bob" through an out-of-band channel
      And "Bob" accepts the invitation from "Alice" and both agents opt to reuse their connections
     Then "Alice" and "Bob" confirm they reused their connections

  Scenario: handshake_protocols: yes | requests~attach: yes | existing_conn: yes
    Given "Alice" creates an out-of-band invitation with a public DID
      And "Bob" connects with "Alice" using the invitation
     When "Alice" creates another out-of-band invitation with the same public DID and an attached offer-credential message
      And "Alice" sends the invitation to "Bob" through an out-of-band channel
      And "Bob" accepts the invitation from "Alice" and both agents opt to reuse their connections
      And "Alice" and "Bob" confirm they reused their connections
      And "Bob" accepts the offer-credential message from "Alice"
     Then "Bob" is issued the credential
