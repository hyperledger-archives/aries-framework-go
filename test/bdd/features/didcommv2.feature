#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@didcommv2
Feature: DIDComm v2 features
  @didcommv2_did_rotation
  Scenario: DIDComm v2 connection using OOBv2 with DID rotation, demonstrated with present proof v3
    Given "P" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
      And "V" agent is running on "localhost" port "9081" with controller "https://localhost:9082"

    Given "V" sends OOBv2 invitation to "P" to establish connection through PresentProof controller

    When "P" sends a propose presentation v3 to "V" through PresentProof controller

     And "V" waits to receive a message from "P" through PresentProof controller
     And "V" rotates its connection to "P" to a new peer DID using controller

     And "V" sends "request_presentation_v3_default.json" to "P" through PresentProof controller
     And "P" negotiates about the request presentation v3 with a proposal through PresentProof controller
     And "V" sends "request_presentation_v3_default.json" to "P" through PresentProof controller
     And "P" sends "presentation_v3_default.json" to "V" through PresentProof controller

    Then "V" successfully accepts a presentation with "license-test-v3" name through PresentProof controller
     And "V" checks that presentation is being stored under the "license-test-v3" name
