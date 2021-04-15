#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@introduce
Feature: Introduce protocol
  @skip_proposal
  Scenario: Alice has Carol's public out-of-band invitation
    Given   "Bob,Carol" exchange DIDs with "Alice"
    And   "Alice" sends introduce proposal to the "Bob" with "Carol" out-of-band invitation
    When   "Bob" wants to know "Carol" and sends introduce response with approve
    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,delivering,delivering,done,done"
    Then  "Bob" has did exchange connection with "Carol"
    And   "Bob" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,done,done" and stop

  @skip_proposal_with_request
  Scenario: Alice has a Carol's public out-of-band invitation. The protocol starts with introduce request.
    Given   "Bob,Carol" exchange DIDs with "Alice"
    And   "Bob" sends introduce request to the "Alice" asking about "Carol"
    And   "Alice" sends introduce proposal back to the requester with public out-of-band invitation
    When   "Bob" wants to know "Carol" and sends introduce response with approve
    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,delivering,delivering,done,done"
    Then  "Bob" has did exchange connection with "Carol"
    And   "Bob" checks the history of introduce protocol events "requesting,requesting,deciding,deciding,waiting,waiting,done,done" and stop

  @skip_proposal_stop
  Scenario: Alice has a Carol's public out-of-band invitation but Bob does not want the introduction
    Given   "Bob,Carol" exchange DIDs with "Alice"
    And   "Alice" sends introduce proposal to the "Bob" with "Carol" out-of-band invitation
    When   "Bob" doesn't want to know "Carol" and sends introduce response
    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,abandoning,abandoning,done,done"
    And   "Bob" checks the history of introduce protocol events "deciding,deciding,abandoning,abandoning,done,done" and stop

  @skip_proposal_stop_with_request
  Scenario: Alice has a Carol's public out-of-band invitation but Bob does not want the introduction. The protocol starts with introduce request.
    Given   "Bob,Carol" exchange DIDs with "Alice"
    And   "Bob" sends introduce request to the "Alice" asking about "Carol"
    When   "Alice" sends introduce proposal back to the requester with public out-of-band invitation
    And   "Bob" doesn't want to know "Carol" and sends introduce response
    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,abandoning,abandoning,done,done"
    And   "Bob" checks the history of introduce protocol events "requesting,requesting,deciding,deciding,abandoning,abandoning,done,done" and stop

  @proposal
  Scenario: Bob sends a response with approve and an out-of-band invitation.
    Given   "Bob,Carol" exchange DIDs with "Alice"
    When   "Alice" sends introduce proposal to the "Bob" and "Carol"
    And   "Bob" wants to know "Carol" and sends introduce response with approve and provides an out-of-band invitation
    And   "Carol" wants to know "Bob" and sends introduce response with approve
    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,arranging,arranging,arranging,arranging,delivering,delivering,confirming,confirming,done,done"
    And   "Bob" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,done,done"
    Then  "Carol" has did exchange connection with "Bob"
    And   "Carol" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,done,done" and stop

    # TODO this test must be reimplemented after outofband was updated.
    #  Reason: attachments in outofband invitations are to be *responded to*, not to be replayed
    #  back to the sender, which is what this test is relying on.
    #  Issue: https://github.com/hyperledger/aries-framework-go/issues/2735.
#  @proposal_response_with_embedded_route_request
#  Scenario: Bob sends a response with approve and an out-of-band invitation with an embedded route-request.
#    Given   "Alice-Router,Bob" exchange DIDs with "Alice"
#    And   "Alice-Router" creates a route exchange client
#    When   "Alice" sends introduce proposal to the "Alice-Router" and "Bob"
#    And   "Alice-Router" wants to know "Bob" and sends introduce response with approve and provides an out-of-band invitation with an embedded "route-request"
#    And   "Bob" wants to know "Alice-Router" and sends introduce response with approve
#    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,arranging,arranging,arranging,arranging,delivering,delivering,confirming,confirming,done,done"
#    And   "Alice-Router" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,done,done"
#    Then  "Bob" has did exchange connection with "Alice-Router"
#    And   "Bob" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,done,done" and stop
#    Then  "Bob" confirms route registration with "Alice-Router"

  @proposal_with_request
  Scenario: Bob sends a response with approve and an out-of-band invitation. The protocol starts with introduce request
    Given   "Bob,Carol" exchange DIDs with "Alice"
    When   "Bob" sends introduce request to the "Alice" asking about "Carol"
    And   "Alice" sends introduce proposal back to the "Bob" and requested introduce
    And   "Bob" wants to know "Carol" and sends introduce response with approve and provides an out-of-band invitation
    And   "Carol" wants to know "Bob" and sends introduce response with approve
    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,arranging,arranging,delivering,delivering,confirming,confirming,done,done"
    And   "Bob" checks the history of introduce protocol events "requesting,requesting,deciding,deciding,waiting,waiting,done,done"
    Then  "Carol" has did exchange connection with "Bob"
    And   "Carol" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,done,done" and stop

  @proposal_unusual
  Scenario: Carol sends a response with approve and an out-of-band invitation
    Given   "Bob,Carol" exchange DIDs with "Alice"
    When   "Alice" sends introduce proposal to the "Bob" and "Carol"
    And   "Bob" wants to know "Carol" and sends introduce response with approve
    And   "Carol" wants to know "Bob" and sends introduce response with approve and provides an out-of-band invitation
    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,arranging,arranging,arranging,arranging,delivering,delivering,confirming,confirming,done,done"
    And   "Bob" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,done,done"
    Then  "Bob" has did exchange connection with "Carol"
    And   "Carol" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,done,done" and stop

  @proposal_unusual_with_request
  Scenario: Carol sends a response with approve and an out-of-band invitation. The protocol starts with introduce request
    Given   "Bob,Carol" exchange DIDs with "Alice"
    When   "Bob" sends introduce request to the "Alice" asking about "Carol"
    And   "Alice" sends introduce proposal back to the "Bob" and requested introduce
    And   "Bob" wants to know "Carol" and sends introduce response with approve
    And   "Carol" wants to know "Bob" and sends introduce response with approve and provides an out-of-band invitation
    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,arranging,arranging,delivering,delivering,confirming,confirming,done,done"
    And   "Bob" checks the history of introduce protocol events "requesting,requesting,deciding,deciding,waiting,waiting,done,done"
    Then  "Bob" has did exchange connection with "Carol"
    And   "Carol" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,done,done" and stop

  @proposal_no_oob_message
  Scenario: No one provided an out-of-band message
    Given   "Bob,Carol" exchange DIDs with "Alice"
    And   "Alice" sends introduce proposal to the "Bob" and "Carol"
    And   "Bob" wants to know "Carol" and sends introduce response with approve
    And   "Carol" wants to know "Bob" and sends introduce response with approve
    Then "Bob" receives problem report message (Introduce)
    Then "Carol" receives problem report message (Introduce)
    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,arranging,arranging,arranging,arranging,delivering,delivering,abandoning,abandoning,done,done"
    And   "Bob" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,abandoning,abandoning,done,done"
    And   "Carol" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,abandoning,abandoning,done,done" and stop

  @proposal_no_oob_message_with_request
  Scenario: No one provided an out-of-band message. The protocol starts with introduce request
    Given   "Bob,Carol" exchange DIDs with "Alice"
    When   "Bob" sends introduce request to the "Alice" asking about "Carol"
    Then   "Alice" sends introduce proposal back to the "Bob" and requested introduce
    And   "Bob" wants to know "Carol" and sends introduce response with approve
    And   "Carol" wants to know "Bob" and sends introduce response with approve
    Then "Bob" receives problem report message (Introduce)
    Then "Carol" receives problem report message (Introduce)
    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,arranging,arranging,delivering,delivering,abandoning,abandoning,done,done"
    And   "Bob" checks the history of introduce protocol events "requesting,requesting,deciding,deciding,waiting,waiting,abandoning,abandoning,done,done"
    And   "Carol" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,abandoning,abandoning,done,done" and stop

  @proposal_stop
  Scenario: Bob does not want the introduction
    Given   "Bob,Carol" exchange DIDs with "Alice"
    When   "Alice" sends introduce proposal to the "Bob" and "Carol"
    And   "Bob" doesn't want to know "Carol" and sends introduce response
    And   "Carol" wants to know "Bob" and sends introduce response with approve
    Then "Carol" receives problem report message (Introduce)
    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,arranging,arranging,arranging,arranging,abandoning,abandoning,done,done"
    And   "Bob" checks the history of introduce protocol events "deciding,deciding,abandoning,abandoning,done,done"
    And   "Carol" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,abandoning,abandoning,done,done" and stop

  @proposal_stop_with_request
  Scenario: Bob does not want the introduction. The protocol starts with introduce request
    Given   "Bob,Carol" exchange DIDs with "Alice"
    When   "Bob" sends introduce request to the "Alice" asking about "Carol"
    Then   "Alice" sends introduce proposal back to the "Bob" and requested introduce
    And   "Bob" doesn't want to know "Carol" and sends introduce response
    And   "Carol" wants to know "Bob" and sends introduce response with approve
    Then "Carol" receives problem report message (Introduce)
    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,arranging,arranging,abandoning,abandoning,done,done"
    And   "Bob" checks the history of introduce protocol events "requesting,requesting,deciding,deciding,abandoning,abandoning,done,done"
    And   "Carol" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,abandoning,abandoning,done,done" and stop

  @proposal_stop_unusual
  Scenario: Carol does not want the introduction
    Given   "Bob,Carol" exchange DIDs with "Alice"
    When   "Alice" sends introduce proposal to the "Bob" and "Carol"
    And   "Bob" wants to know "Carol" and sends introduce response with approve
    And   "Carol" doesn't want to know "Bob" and sends introduce response
    Then "Bob" receives problem report message (Introduce)
    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,arranging,arranging,arranging,arranging,abandoning,abandoning,done,done"
    And   "Bob" checks the history of introduce protocol events "deciding,deciding,waiting,waiting,abandoning,abandoning,done,done"
    And   "Carol" checks the history of introduce protocol events "deciding,deciding,abandoning,abandoning,done,done" and stop

  @proposal_stop_unusual_with_request
  Scenario: Carol does not want the introduction. The protocol starts with introduce request
    Given   "Bob,Carol" exchange DIDs with "Alice"
    When   "Bob" sends introduce request to the "Alice" asking about "Carol"
    Then   "Alice" sends introduce proposal back to the "Bob" and requested introduce
    And   "Bob" wants to know "Carol" and sends introduce response with approve
    And   "Carol" doesn't want to know "Bob" and sends introduce response
    Then "Bob" receives problem report message (Introduce)
    Then   "Alice" checks the history of introduce protocol events "arranging,arranging,arranging,arranging,arranging,arranging,abandoning,abandoning,done,done"
    And   "Bob" checks the history of introduce protocol events "requesting,requesting,deciding,deciding,waiting,waiting,abandoning,abandoning,done,done"
    And   "Carol" checks the history of introduce protocol events "deciding,deciding,abandoning,abandoning,done,done" and stop

  @proposal_introducer_stop_with_request
  Scenario: Introducer stops the protocol after receiving second approve. The protocol starts with introduce request
    Given   "Bob" exchange DIDs with "Alice"
    When   "Bob" sends introduce request to the "Alice" asking about "Carol"
    And   "Alice" stops the introduce protocol
    Then "Bob" receives problem report message (Introduce)
    Then   "Alice" checks the history of introduce protocol events "abandoning,abandoning,done,done"
    And   "Bob" checks the history of introduce protocol events "requesting,requesting,abandoning,abandoning,done,done" and stop
