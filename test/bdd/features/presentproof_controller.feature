#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0037-present-proof

@all
@controller
@present_proof_controller
Feature: Present Proof using controller API

  Scenario: The Verifier begins with a presentation request
    Given "Alice" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
      And "Bob" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
      And "Alice" has established connection with "Bob" through PresentProof controller

    When  "Alice" sends "request_presentation_default.json" to "Bob" through PresentProof controller
      And "Bob" sends "presentation_default.json" to "Alice" through PresentProof controller

    Then  "Alice" successfully accepts a presentation with "passport" name through PresentProof controller
      And "Alice" checks that presentation is being stored under the "passport" name

  @present_proof_controller_bbs
  Scenario: The Verifier begins with a presentation request (BBS+)
    Given "Jennifer" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Julia" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
    And "Jennifer" has established connection with "Julia" through PresentProof controller

    When  "Jennifer" sends "request_presentation_bbs.json" to "Julia" through PresentProof controller
    When  "Julia" sends "presentation_bbs.json" to "Jennifer" through PresentProof controller

    Then  "Jennifer" successfully accepts a presentation with "bbs-passport" name through PresentProof controller
    And "Jennifer" checks that presentation is being stored under the "bbs-passport" name

  Scenario: The Prover begins with a presentation proposal
    Given "Carol" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
      And "Dan" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
      And "Carol" has established connection with "Dan" through PresentProof controller

    When  "Carol" sends a propose presentation to "Dan" through PresentProof controller
      And "Dan" sends "request_presentation_default.json" to "Carol" through PresentProof controller
      And "Carol" sends "presentation_default.json" to "Dan" through PresentProof controller

    Then  "Dan" successfully accepts a presentation with "degree" name through PresentProof controller
      And "Dan" checks that presentation is being stored under the "degree" name

  Scenario: The Prover begins with a presentation proposal (negotiation)
    Given "Peggy" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
      And "Victor" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
      And "Peggy" has established connection with "Victor" through PresentProof controller

    When  "Peggy" sends a propose presentation to "Victor" through PresentProof controller
      And "Victor" sends "request_presentation_default.json" to "Peggy" through PresentProof controller
      And "Peggy" negotiates about the request presentation with a proposal through PresentProof controller
      And "Victor" sends "request_presentation_default.json" to "Peggy" through PresentProof controller
      And "Peggy" sends "presentation_default.json" to "Victor" through PresentProof controller

    Then  "Victor" successfully accepts a presentation with "license" name through PresentProof controller
      And "Victor" checks that presentation is being stored under the "license" name

  Scenario: The Verifier begins with a presentation request (multiple attachments)
    Given "Johnny" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Julia" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
    And "Johnny" has established connection with "Julia" through PresentProof controller

    When  "Johnny" sends "request_presentation_multiple_attachments.json" to "Julia" through PresentProof controller
    When  "Julia" sends "presentation_multiple_attachments.json" to "Johnny" through PresentProof controller

    Then  "Johnny" successfully accepts a presentation with "custom-vp" name through PresentProof controller
    And "Johnny" checks that presentation is being stored under the "custom-vp" name
