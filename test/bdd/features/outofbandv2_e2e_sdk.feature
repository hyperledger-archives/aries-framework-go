#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

# Reference : https://identity.foundation/didcomm-messaging/spec/#out-of-band-messages

@all
@outofbandv2
@outofbandv2_e2e_sdk
Feature: Out-Of-Band V2 protocol (Go API)

  Background:
    Given all agents are using Media Type Profiles "didcomm/aip1,didcomm/aip2;env=rfc19,didcomm/aip2;env=rfc587,didcomm/v2"
    Given "Alice" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree" and auto triggered services
      And "Bob" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree" and auto triggered services

  Scenario: The Verifier begins with a request of oob v2 invitation wrapping a proof presentation v3 request as target goal
    Given "Alice" creates public DID for did method "sidetree"
    And "Bob" creates public DID for did method "sidetree"
    Then "Alice" waits for public did to become available in sidetree for up to 10 seconds
    And "Bob" waits for public did to become available in sidetree for up to 10 seconds
    Then "Alice" creates an out-of-band-v2 invitation with embedded present proof v3 request as target service
    And "Alice" sends the request to "Bob" and he accepts it by processing both OOBv2 and the embedded present proof v3 request
