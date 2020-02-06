
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@introduce
Feature: Introduce protocol
  @skip_proposal
  Scenario: Alice has a Carol's public invitation
    Given   "Bob,Carol" exchange DIDs with "Alice"
      And   "Alice" sends introduce proposal to the "Bob" with "Carol" invitation

    When   "Bob" wants to know "Carol" and sends introduce response with approve
      And   "Alice" forwards Carol's invitation to Bob

    Then   "Bob" and "Carol" exchange DIDs

    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,delivering,delivering,done,done"
      And   "Bob" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,done,done"

  @skip_proposal_with_request
  Scenario: Alice has a Carol's public invitation. The protocol starts with request.
    Given   "Bob,Carol" exchange DIDs with "Alice"
      And   "Bob" sends introduce request to the "Alice" asking about "Carol"
      And   "Alice" sends introduce proposal back to the requester with pub invitation

    When   "Bob" wants to know "Carol" and sends introduce response with approve
    And   "Alice" forwards Carol's invitation to Bob

    Then   "Bob" and "Carol" exchange DIDs

    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,delivering,delivering,done,done"
      And   "Bob" checks the history of introduce protocol events "requesting,requesting,deciding,deciding,waiting,waiting,done,done"

  @skip_proposal_stop
  Scenario: Alice has a Carol's public invitation but Bob does not want the introduction
    Given   "Bob,Carol" exchange DIDs with "Alice"
      And   "Alice" sends introduce proposal to the "Bob" with "Carol" invitation

    When   "Bob" doesn't want to know "Carol" and sends introduce response
      And   "Alice" continue with the introduce protocol

    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,delivering,delivering,abandoning,abandoning,done,done"
      And   "Bob" checks the history of introduce protocol events "deciding,deciding,abandoning,abandoning,done,done"

  @skip_proposal_stop_with_request
  Scenario: Alice has a Carol's public invitation but Bob does not want the introduction. The protocol starts with request.
    Given   "Bob,Carol" exchange DIDs with "Alice"
      And   "Bob" sends introduce request to the "Alice" asking about "Carol"

    When   "Alice" sends introduce proposal back to the requester with pub invitation
      And   "Bob" doesn't want to know "Carol" and sends introduce response

    Then   "Alice" continue with the introduce protocol

    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,delivering,delivering,abandoning,abandoning,done,done"
      And   "Bob" checks the history of introduce protocol events "requesting,requesting,deciding,deciding,abandoning,abandoning,done,done"

  @skip_proposal_introducer_stop
  Scenario: Alice stops the protocol after receiving approve
    Given   "Bob,Carol" exchange DIDs with "Alice"
      And   "Alice" sends introduce proposal to the "Bob" with "Carol" invitation

    When   "Bob" wants to know "Carol" and sends introduce response with approve
      And   "Alice" stops the introduce protocol

    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,abandoning,abandoning,done,done"
      And   "Bob" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,abandoning,abandoning,done,done"

  @skip_proposal_introducer_stop_with_request
  Scenario: Alice stops the protocol after receiving approve. The protocol starts with request
    Given   "Bob,Carol" exchange DIDs with "Alice"
      And   "Bob" sends introduce request to the "Alice" asking about "Carol"

    When   "Alice" sends introduce proposal back to the requester with pub invitation
      And   "Bob" wants to know "Carol" and sends introduce response with approve

    Then   "Alice" stops the introduce protocol
      And   "Alice" checks the history of introduce protocol events "arranging,arranging,abandoning,abandoning,done,done"
      And   "Bob" checks the history of introduce protocol events "requesting,requesting,deciding,deciding,waiting,waiting,abandoning,abandoning,done,done"

  @proposal
  Scenario: Bob sends a response with approve and an invitation.
    Given   "Bob,Carol" exchange DIDs with "Alice"
      And   "Bob" creates introduce client with an invitation

    When   "Alice" sends introduce proposal to the "Bob" and "Carol"
      And   "Bob" wants to know "Carol" and sends introduce response with approve
      And   "Alice" continue with the introduce protocol

    When   "Carol" wants to know "Bob" and sends introduce response with approve
      And   "Alice" forwards Bob's invitation to Carol

    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,delivering,delivering,confirming,confirming,done,done"
      And   "Bob" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,done,done"
      And   "Carol" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,done,done"

  @proposal_with_request
  Scenario: Bob sends a response with approve and an invitation the protocol starts with request
    Given   "Bob,Carol" exchange DIDs with "Alice"
      And   "Bob" creates introduce client with an invitation

    When   "Bob" sends introduce request to the "Alice" asking about "Carol"
      And   "Alice" sends introduce proposal back to the "Bob" and requested introduce

    When   "Bob" wants to know "Carol" and sends introduce response with approve
      And   "Alice" continue with the introduce protocol

    When   "Carol" wants to know "Bob" and sends introduce response with approve
      And   "Alice" forwards Bob's invitation to Carol

    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,delivering,delivering,confirming,confirming,done,done"
      And   "Bob" checks the history of introduce protocol events "requesting,requesting,deciding,deciding,waiting,waiting,done,done"
      And   "Carol" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,done,done"

  @proposal_unusual
  Scenario: Carol sends a response with approve and an invitation
    Given   "Bob,Carol" exchange DIDs with "Alice"
      And   "Carol" creates introduce client with an invitation

    When   "Alice" sends introduce proposal to the "Bob" and "Carol"
      And   "Bob" wants to know "Carol" and sends introduce response with approve

    When   "Alice" continue with the introduce protocol
      And   "Carol" wants to know "Bob" and sends introduce response with approve

    When  "Alice" forwards Carol's invitation to Bob

    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,delivering,delivering,confirming,confirming,done,done"
      And   "Bob" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,done,done"
      And   "Carol" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,done,done"

  @proposal_unusual_with_request
  Scenario: Carol sends a response with approve and an invitation the protocol starts with request
    Given   "Bob,Carol" exchange DIDs with "Alice"
      And   "Carol" creates introduce client with an invitation

    When   "Bob" sends introduce request to the "Alice" asking about "Carol"
      And   "Alice" sends introduce proposal back to the "Bob" and requested introduce

    When   "Bob" wants to know "Carol" and sends introduce response with approve
      And   "Alice" continue with the introduce protocol

    When   "Carol" wants to know "Bob" and sends introduce response with approve
      And   "Alice" forwards Carol's invitation to Bob

    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,delivering,delivering,confirming,confirming,done,done"
      And   "Bob" checks the history of introduce protocol events "requesting,requesting,deciding,deciding,waiting,waiting,done,done"
      And   "Carol" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,done,done"

  @proposal_no_invitation
  Scenario: No one provided an invitation
    Given   "Bob,Carol" exchange DIDs with "Alice"
      And   "Alice" sends introduce proposal to the "Bob" and "Carol"

    When   "Bob" wants to know "Carol" and sends introduce response with approve
      And   "Alice" continue with the introduce protocol

    When   "Carol" wants to know "Bob" and sends introduce response with approve
      And   "Alice" continue with the introduce protocol

    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,delivering,delivering,abandoning,abandoning,done,done"
      And   "Bob" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,abandoning,abandoning,done,done"
      And   "Carol" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,abandoning,abandoning,done,done"

  @proposal_no_invitation_with_request
  Scenario: No one provided an invitation the protocol starts with request
    Given   "Bob,Carol" exchange DIDs with "Alice"
      And   "Bob" sends introduce request to the "Alice" asking about "Carol"

    When   "Alice" sends introduce proposal back to the "Bob" and requested introduce
      And   "Bob" wants to know "Carol" and sends introduce response with approve

    When   "Alice" continue with the introduce protocol
      And   "Carol" wants to know "Bob" and sends introduce response with approve
      And   "Alice" continue with the introduce protocol

    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,delivering,delivering,abandoning,abandoning,done,done"
      And   "Bob" checks the history of introduce protocol events "requesting,requesting,deciding,deciding,waiting,waiting,abandoning,abandoning,done,done"
      And   "Carol" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,abandoning,abandoning,done,done"

  @proposal_stop
  Scenario: Bob does not want the introduction
    Given   "Bob,Carol" exchange DIDs with "Alice"

    When   "Alice" sends introduce proposal to the "Bob" and "Carol"
      And   "Bob" doesn't want to know "Carol" and sends introduce response
      And   "Alice" continue with the introduce protocol

    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,abandoning,abandoning,done,done"
      And   "Bob" checks the history of introduce protocol events "deciding,deciding,abandoning,abandoning,done,done"

  @proposal_stop_with_request
  Scenario: Bob does not want the introduction the protocol starts with request
    Given   "Bob,Carol" exchange DIDs with "Alice"

    When   "Bob" sends introduce request to the "Alice" asking about "Carol"
      And   "Alice" sends introduce proposal back to the "Bob" and requested introduce
      And   "Bob" doesn't want to know "Carol" and sends introduce response
      And   "Alice" continue with the introduce protocol

    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,abandoning,abandoning,done,done"
    And   "Bob" checks the history of introduce protocol events "requesting,requesting,deciding,deciding,abandoning,abandoning,done,done"

  @proposal_stop_unusual
  Scenario: Carol does not want the introduction
    Given   "Bob,Carol" exchange DIDs with "Alice"

    When   "Alice" sends introduce proposal to the "Bob" and "Carol"
      And   "Bob" wants to know "Carol" and sends introduce response with approve
      And   "Alice" continue with the introduce protocol

    When   "Carol" doesn't want to know "Bob" and sends introduce response
      And   "Alice" continue with the introduce protocol

    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,delivering,delivering,abandoning,abandoning,done,done"
      And   "Bob" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,abandoning,abandoning,done,done"
      And   "Carol" checks the history of introduce protocol events "deciding,deciding,abandoning,abandoning,done,done"

  @proposal_stop_unusual_with_request
  Scenario: Carol does not want the introduction the protocol starts with request
    Given   "Bob,Carol" exchange DIDs with "Alice"

    When   "Bob" sends introduce request to the "Alice" asking about "Carol"
      And   "Alice" sends introduce proposal back to the "Bob" and requested introduce
      And   "Bob" wants to know "Carol" and sends introduce response with approve

    When   "Alice" continue with the introduce protocol
      And   "Carol" doesn't want to know "Bob" and sends introduce response
      And   "Alice" continue with the introduce protocol

    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,delivering,delivering,abandoning,abandoning,done,done"
    And   "Bob" checks the history of introduce protocol events "requesting,requesting,deciding,deciding,waiting,waiting,abandoning,abandoning,done,done"
    And   "Carol" checks the history of introduce protocol events "deciding,deciding,abandoning,abandoning,done,done"

  @proposal_introducer_stop
  Scenario: Introducer stops the protocol after receiving approve
    Given   "Bob,Carol" exchange DIDs with "Alice"

    When  "Bob" creates introduce client with an invitation
      And   "Alice" sends introduce proposal to the "Bob" and "Carol"
      And   "Bob" wants to know "Carol" and sends introduce response with approve
      And   "Alice" stops the introduce protocol

    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,abandoning,abandoning,done,done"
      And   "Bob" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,abandoning,abandoning,done,done"

  @proposal_introducer_stop_with_request
  Scenario: Introducer stops the protocol after receiving approve the protocol starts with request
    Given   "Bob,Carol" exchange DIDs with "Alice"

    When   "Bob" creates introduce client with an invitation
      And   "Bob" sends introduce request to the "Alice" asking about "Carol"
      And   "Alice" sends introduce proposal back to the "Bob" and requested introduce
      And   "Bob" wants to know "Carol" and sends introduce response with approve
      And   "Alice" stops the introduce protocol

    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,abandoning,abandoning,done,done"
    And   "Bob" checks the history of introduce protocol events "requesting,requesting,deciding,deciding,waiting,waiting,abandoning,abandoning,done,done"

  @proposal_introducer_second_stop
  Scenario: Introducer stops the protocol after receiving second approve
    Given   "Bob,Carol" exchange DIDs with "Alice"

    When   "Bob" creates introduce client with an invitation
      And   "Alice" sends introduce proposal to the "Bob" and "Carol"
      And   "Bob" wants to know "Carol" and sends introduce response with approve
      And   "Alice" continue with the introduce protocol
      And   "Carol" wants to know "Bob" and sends introduce response with approve
      And   "Alice" stops the introduce protocol

    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,abandoning,abandoning,done,done"
    And   "Bob" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,abandoning,abandoning,done,done"
    And   "Carol" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,abandoning,abandoning,done,done"


  @proposal_introducer_second_stop_with_request
  Scenario: Introducer stops the protocol after receiving second approve the protocol starts with request
    Given   "Bob,Carol" exchange DIDs with "Alice"

    When   "Bob" creates introduce client with an invitation
      And   "Bob" sends introduce request to the "Alice" asking about "Carol"
      And   "Alice" sends introduce proposal back to the "Bob" and requested introduce
      And   "Bob" wants to know "Carol" and sends introduce response with approve
      And   "Alice" continue with the introduce protocol
      And   "Carol" wants to know "Bob" and sends introduce response with approve
      And   "Alice" stops the introduce protocol

    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,abandoning,abandoning,done,done"
      And   "Bob" checks the history of introduce protocol events "requesting,requesting,deciding,deciding,waiting,waiting,abandoning,abandoning,done,done"
      And   "Carol" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,abandoning,abandoning,done,done"