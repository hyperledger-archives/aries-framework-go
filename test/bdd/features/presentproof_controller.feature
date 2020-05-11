#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0037-present-proof

@all
@present_proof_controller
Feature: Present Proof using controller API

  Scenario: The Verifier begins with a presentation request
    Given "Alice" agent is running on "localhost" port "8081" with controller "http://localhost:8082"
      And "Bob" agent is running on "localhost" port "9081" with controller "http://localhost:9082"
      And "Alice" has established connection with "Bob" through PresentProof controller

    When  "Alice" sends a request presentation to "Bob" through PresentProof controller
      And "Bob" accepts a request and sends a presentation to the Verifier through PresentProof controller

    Then  "Alice" successfully accepts a presentation through PresentProof controller

  Scenario: The Prover begins with a presentation proposal
    Given "Carol" agent is running on "localhost" port "8081" with controller "http://localhost:8082"
      And "Dan" agent is running on "localhost" port "9081" with controller "http://localhost:9082"
      And "Carol" has established connection with "Dan" through PresentProof controller

    When  "Carol" sends a propose presentation to "Dan" through PresentProof controller
      And "Dan" accepts a proposal and sends a request to the Prover through PresentProof controller
      And "Carol" accepts a request and sends a presentation to the Verifier through PresentProof controller

    Then  "Dan" successfully accepts a presentation through PresentProof controller

  Scenario: The Prover begins with a presentation proposal (negotiation)
    Given "Peggy" agent is running on "localhost" port "8081" with controller "http://localhost:8082"
      And "Victor" agent is running on "localhost" port "9081" with controller "http://localhost:9082"
      And "Peggy" has established connection with "Victor" through PresentProof controller

    When  "Peggy" sends a propose presentation to "Victor" through PresentProof controller
      And "Victor" accepts a proposal and sends a request to the Prover through PresentProof controller
      And "Peggy" negotiates about the request presentation with a proposal through PresentProof controller
      And "Victor" accepts a proposal and sends a request to the Prover through PresentProof controller
      And "Peggy" accepts a request and sends a presentation to the Verifier through PresentProof controller

    Then  "Victor" successfully accepts a presentation through PresentProof controller
