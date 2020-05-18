#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@presentproof
Feature: Present Proof protocol
  @begin_with_request_presentation
  Scenario: The Verifier begins with a request presentation
    Given "Alice" exchange DIDs with "Bob"
    Then "Alice" sends a request presentation to the "Bob"
    And "Bob" accepts a request and sends a presentation to the "Alice"
    And "Alice" accepts a presentation with name "license"
    And "Alice" checks that presentation is being stored under "license" name
    Then "Bob" checks the history of events "request-received,request-received,presentation-sent,presentation-sent,done,done"
  @decline_presentation
  Scenario: The Verifier declines presentation
    Given "Thomas" exchange DIDs with "Paul"
    Then "Thomas" sends a request presentation to the "Paul"
    And "Paul" accepts a request and sends a presentation to the "Thomas"
    And "Thomas" declines presentation
    Then "Paul" checks the history of events "request-received,request-received,presentation-sent,presentation-sent,abandoning,abandoning,done,done"
    And "Thomas" checks the history of events "request-sent,request-sent,abandoning,abandoning,done,done"
  @decline_request_presentation
  Scenario: The Prover declines a request presentation
    Given "Liam" exchange DIDs with "Samuel"
    Then "Liam" sends a request presentation to the "Samuel"
    And "Samuel" declines a request presentation
    Then "Samuel" checks the history of events "abandoning,abandoning,done,done"
    And "Liam" checks the history of events "request-sent,request-sent,abandoning,abandoning,done,done"
  @begin_with_propose_presentation
  Scenario: The Prover begins with a proposal
    Given "Carol" exchange DIDs with "Andrew"
    Then "Carol" sends a propose presentation to the "Andrew"
    And "Andrew" accepts a proposal and sends a request to the Prover
    And "Carol" accepts a request and sends a presentation to the "Andrew"
    And "Andrew" accepts a presentation with name "passport"
    And "Andrew" checks that presentation is being stored under "passport" name
    Then "Carol" checks the history of events "proposal-sent,proposal-sent,request-received,request-received,presentation-sent,presentation-sent,done,done"
  @decline_propose_presentation
  Scenario: The Verifier declines a propose presentation
    Given "Michael" exchange DIDs with "David"
    Then "Michael" sends a propose presentation to the "David"
    And "David" declines a propose presentation
    Then "Michael" checks the history of events "proposal-sent,proposal-sent,abandoning,abandoning,done,done"
    And "David" checks the history of events "abandoning,abandoning,done,done"
  @begin_with_request_presentation_negotiation
  Scenario: The Verifier begins with a request presentation (negotiation)
    Given "William" exchange DIDs with "Felix"
    Then "William" sends a request presentation to the "Felix"
    Then "Felix" negotiates about the request presentation with a proposal
    And "William" accepts a proposal and sends a request to the Prover
    And "Felix" accepts a request and sends a presentation to the "William"
    And "William" accepts a presentation with name "passport"
    And "William" checks that presentation is being stored under "passport" name
    Then "Felix" checks the history of events "request-received,request-received,proposal-sent,proposal-sent,request-received,request-received,presentation-sent,presentation-sent,done,done"
  @begin_with_propose_presentation_negotiation
  Scenario: The Prover begins with a proposal (negotiation)
    Given "Jason" exchange DIDs with "Jesse"
    Then "Jason" sends a propose presentation to the "Jesse"
    And "Jesse" accepts a proposal and sends a request to the Prover
    Then "Jason" negotiates about the request presentation with a proposal
    And "Jesse" accepts a proposal and sends a request to the Prover
    And "Jason" accepts a request and sends a presentation to the "Jesse"
    And "Jesse" accepts a presentation with name "bachelors degree"
    And "Jesse" checks that presentation is being stored under "bachelors degree" name
    Then "Jason" checks the history of events "proposal-sent,proposal-sent,request-received,request-received,proposal-sent,proposal-sent,request-received,request-received,presentation-sent,presentation-sent,done,done"
