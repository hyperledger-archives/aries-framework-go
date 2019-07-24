#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange#2-exchange-response

@all
Feature: Decentralized Identifier(DID) exchange between the agents

  #Invitation Message with Public Invitation DID.
  @didExchangePublicDid
  Scenario: Invited: Share Invitation with Public DID
    # Inviter Agent must be capable of creating DIDs and endpoints at which they are prepared to interact.
    Given Alice agent is running on "https://localhost:" port "8080"
    And   Alice prepares invitation using  public did "did:sov:QmWbsNYhMrjHiqZDTUTEJs"
    Then  Invitation URL is available at "http://localhost:8080/ssi?c_i=eyJAdHlWVOYzN6N1BZWG1kNTR="

  Scenario: Requested: Bob sends exchange request to Alice
    # Invitee agent must  be capable of receiving invitations over traditional communication channels of some type, and acting on it in a way that leads to successful interaction.
    Given Bob received invitation URL  "http://localhost:8080/ssi?c_i=eyJAdHlWVOYzN6N1BZWG1kNTR=" from Alice
    Given Bob agent is running on "https://localhost:" port "8180"
    And   Bob parses the invitation URL "http://localhost:8080/ssi?c_i=eyJAdHlWVOYzN6N1BZWG1kNTR="
    Then  Bob sends exchange_request with new did "B.did@B:A" to Alice

  Scenario: Responded: Alice prepares exchange response
    Given Alice received the  exchange request
    And   Alice evaluates the provided DID "B.did@B:A" and validates
    And   Alice provision a new DID "A.did@B:A"
    Then  Alice sends exchange response to Bob

  Scenario: Completed: Did exchange is complete
    Given Bob received the response message
    And   Bob verifies the change_sig provided in the response
    Then  Bob sends "Successful message received" to Alice


  Scenario: Active rejection Error
    Given Bob sends exchange request
    And Alice evaluates the provided DID "B.did@B:A" and DID method validation fails
    Then Alice sends "request_rejected" error with message "unsupported DID method for provided DID"

    #Invitation Message with Keys and URL endpoint
  @didExchangeKeysURL
  Scenario: Invited: Share Invitation with Keys and URL endpoint
    # Inviter Agent must be capable of creating DIDs and endpoints at which they are prepared to interact.
    Given Alice agent is running on "https://localhost:" port "8080"
    And   Alice prepares invitation using service endpoint "https://localhost:8080/endpoint"
    Then  Invitation URL is available at "http://localhost:8080/ssi?c_i=eyJAdHlWVOYzN6N1BZWG1kNTR="


  #Invitation Message with Keys and DID Service Endpoint Reference:
  @didExchangeKeysDID
  Scenario: Invited: Share Invitation with Keys and URL endpoint
    # Inviter Agent must be capable of creating DIDs and endpoints at which they are prepared to interact.
    Given Alice agent is running on "https://localhost:" port "8080"
    And   Alice prepares invitation using DID Service Endpoint Reference "did:sov:A2wBhNYhMrjHiqZDTUYH7u;service=routeid"
    Then  Invitation URL is available at "http://localhost:8080/ssi?c_i=eyJAdHlWVOYzN6N1BZWG1kNTR="




