#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

# Reference : https://identity.foundation/didcomm-messaging/spec/#out-of-band-messages

@all
@controller
@outofbandv2
@outofbandv2_controller
Feature: Out-Of-Band V2 protocol (REST API)

  Background:
    Given "Alice" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Alice" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    And "Bob" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
    And "Bob" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"

  Scenario: The Verifier begins with a request an oob v2 invitation with presentation v3 as target service
    Given "Alice" creates public DID for did method "sidetree"
    And "Bob" creates public DID for did method "sidetree"
    Then "Alice" waits for public did to become available in sidetree for up to 10 seconds
    And "Bob" waits for public did to become available in sidetree for up to 10 seconds
    Then "Alice" creates an out-of-band-v2 invitation with embedded present proof v3 request as target service (controller)
    And "Alice" sends the request to "Bob" and he accepts it by processing both OOBv2 and the embedded present proof v3 request (controller)
