#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0037-present-proof

@controller
@present_proof_controller
Feature: Present Proof using controller API

  @present_proof_presentation_request @present_proof_v2
  Scenario: The Verifier begins with a presentation request
    Given "Alice" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
      And "Bob" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
      And "Alice" has established connection with "Bob" through PresentProof controller

    When  "Alice" sends "request_presentation_default.json" to "Bob" through PresentProof controller
      And "Bob" sends "presentation_default.json" to "Alice" through PresentProof controller

    Then  "Alice" successfully accepts a presentation with "passport_v2" name through PresentProof controller
      And "Alice" checks that presentation is being stored under the "passport_v2" name

  @present_proof_begins_with_presentation_request_v3 @present_proof_v3
  Scenario: The Verifier begins with a presentation request v3
    Given "Arthur" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Logan" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
    And "Arthur" has established DIDComm v2 connection with "Logan" through PresentProof controller

    When  "Arthur" sends "request_presentation_v3_default.json" to "Logan" through PresentProof controller
    And "Logan" sends "presentation_v3_default.json" to "Arthur" through PresentProof controller

    Then  "Arthur" successfully accepts a presentation with "passport_v3" name through PresentProof controller
    And "Arthur" checks that presentation is being stored under the "passport_v3" name

  @present_proof_controller_bbs @present_proof_v2
  Scenario: The Verifier begins with a presentation request (BBS+)
    Given "Jennifer" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Julia" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
    And "Jennifer" has established connection with "Julia" through PresentProof controller

    When  "Jennifer" sends "request_presentation_bbs.json" to "Julia" through PresentProof controller
    When  "Julia" sends "presentation_bbs.json" to "Jennifer" through PresentProof controller

    Then  "Jennifer" successfully accepts a presentation with "bbs-passport" name through PresentProof controller
    And "Jennifer" checks that presentation is being stored under the "bbs-passport" name

  @present_proof_controller_bbs_dl @present_proof_v2
  Scenario: The Verifier begins with a presentation request (BBS+ with embedded context and no ID)
    Given "Jennifer" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Julia" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
    And "Jennifer" has established connection with "Julia" through PresentProof controller

    When  "Jennifer" sends "request_presentation_bbs_dl.json" to "Julia" through PresentProof controller
    When  "Julia" sends "presentation_bbs_dl.json" to "Jennifer" through PresentProof controller

    Then  "Jennifer" successfully accepts a presentation with "bbs-drivers-license" name through PresentProof controller
    And "Jennifer" checks that presentation is being stored under the "bbs-drivers-license" name

  @present_proof_controller_bbs_v3 @present_proof_v3
  Scenario: The Verifier begins with a presentation request v3 (BBS+)
    Given "Harold" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Roger" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
    And "Harold" has established DIDComm v2 connection with "Roger" through PresentProof controller

    When  "Harold" sends "request_presentation_v3_bbs.json" to "Roger" through PresentProof controller
    When  "Roger" sends "presentation_v3_bbs.json" to "Harold" through PresentProof controller

    Then  "Harold" successfully accepts a presentation with "bbs-passport-v3" name through PresentProof controller
    And "Harold" checks that presentation is being stored under the "bbs-passport-v3" name

  @present_proof_v2
  Scenario: The Prover begins with a presentation proposal
    Given "Carol" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
      And "Dan" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
      And "Carol" has established connection with "Dan" through PresentProof controller

    When  "Carol" sends a propose presentation to "Dan" through PresentProof controller
      And "Dan" sends "request_presentation_default.json" to "Carol" through PresentProof controller
      And "Carol" sends "presentation_default.json" to "Dan" through PresentProof controller

    Then  "Dan" successfully accepts a presentation with "degree" name through PresentProof controller
      And "Dan" checks that presentation is being stored under the "degree" name

  @present_proof_v3
  Scenario: The Prover begins with a presentation proposal v3
    Given "Tyler" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Adam" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
    And "Tyler" has established DIDComm v2 connection with "Adam" through PresentProof controller

    When  "Tyler" sends a propose presentation v3 to "Adam" through PresentProof controller
    And "Adam" sends "request_presentation_v3_default.json" to "Tyler" through PresentProof controller
    And "Tyler" sends "presentation_v3_default.json" to "Adam" through PresentProof controller

    Then  "Adam" successfully accepts a presentation with "degree-v3" name through PresentProof controller
    And "Adam" checks that presentation is being stored under the "degree-v3" name

  @present_proof_v2
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

  @present_proof_v3
  Scenario: The Prover begins with a presentation proposal v3 (negotiation)
    Given "Peggy" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Victor" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
    And "Peggy" has established DIDComm v2 connection with "Victor" through PresentProof controller

    When  "Peggy" sends a propose presentation v3 to "Victor" through PresentProof controller
    And "Victor" sends "request_presentation_v3_default.json" to "Peggy" through PresentProof controller
    And "Peggy" negotiates about the request presentation v3 with a proposal through PresentProof controller
    And "Victor" sends "request_presentation_v3_default.json" to "Peggy" through PresentProof controller
    And "Peggy" sends "presentation_v3_default.json" to "Victor" through PresentProof controller

    Then  "Victor" successfully accepts a presentation with "license-v3" name through PresentProof controller
    And "Victor" checks that presentation is being stored under the "license-v3" name

  @present_proof_v2
  Scenario: The Verifier begins with a presentation request (multiple attachments)
    Given "Johnny" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Julia" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
    And "Johnny" has established connection with "Julia" through PresentProof controller

    When  "Johnny" sends "request_presentation_multiple_attachments.json" to "Julia" through PresentProof controller
    When  "Julia" sends "presentation_multiple_attachments.json" to "Johnny" through PresentProof controller

    Then  "Johnny" successfully accepts a presentation with "custom-vp" name through PresentProof controller
    And "Johnny" checks that presentation is being stored under the "custom-vp" name

  @present_proof_v3
  Scenario: The Verifier begins with a presentation request v3 (multiple attachments)
    Given "Johnny" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Julia" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
    And "Johnny" has established DIDComm v2 connection with "Julia" through PresentProof controller

    When  "Johnny" sends "request_presentation_v3_multiple_attachments.json" to "Julia" through PresentProof controller
    When  "Julia" sends "presentation_multiple_v3_attachments.json" to "Johnny" through PresentProof controller

    Then  "Johnny" successfully accepts a presentation with "custom-vp-v3" name through PresentProof controller
    And "Johnny" checks that presentation is being stored under the "custom-vp-v3" name

  @present_proof_redirect_ack @present_proof_v2
  Scenario: The Verifier begins with a presentation request (redirect)
    Given "Ginger" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Leo" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
    And "Ginger" has established connection with "Leo" through PresentProof controller

    When  "Ginger" sends "request_presentation_default.json" to "Leo" through PresentProof controller
    And "Leo" sends "presentation_default.json" to "Ginger" through PresentProof controller

    Then  "Ginger" successfully accepts a presentation with "passport_redirect" name and "https://example.com/success" redirect through PresentProof controller
    And "Ginger" checks that presentation is being stored under the "passport_redirect" name
    And "Leo" validates present proof state "done" and redirect "https://example.com/success" with status "OK" through PresentProof controller

  @present_proof_redirect_problem_report @present_proof_v2
  Scenario: The Verifier begins with a presentation request (redirect abandoned)
    Given "Ginger" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Leo" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
    And "Ginger" has established connection with "Leo" through PresentProof controller

    When  "Ginger" sends "request_presentation_default.json" to "Leo" through PresentProof controller
    And "Leo" sends "presentation_default.json" to "Ginger" through PresentProof controller

    Then  "Ginger" declines presentation "passport_redirect_problem" from "Leo" and redirects prover to "https://example.com/error" through PresentProof controller
    And "Leo" validates present proof state "abandoned" and redirect "https://example.com/error" with status "FAIL" through PresentProof controller
