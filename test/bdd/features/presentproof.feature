#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

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
  @begin_with_request_presentation_v3
  Scenario: The Verifier begins with a request presentation v3
    Given "Jonny" exchange DIDs V2 with "Robert"
    Then "Jonny" sends a request presentation v3 to the "Robert"
    And "Robert" accepts a request and sends a presentation v3 to the "Jonny"
    And "Jonny" accepts a presentation with name "license"
    And "Jonny" checks that presentation is being stored under "license" name
    Then "Robert" checks the history of events "request-received,request-received,presentation-sent,presentation-sent,done,done"
  @begin_with_request_presentation_bbs
  Scenario: The Verifier begins with a request presentation (BBS+)
    Given "Julia" exchange DIDs with "Max"
    Then "Julia" sends a request presentation with presentation definition to the "Max"
    And "Max" accepts a request and sends credentials with BBS to the "Julia" and proof "BbsBlsSignature2020"
    And "Julia" accepts a presentation with name "bbs-license"
    And "Julia" checks that presentation is being stored under "bbs-license" name and has "BbsBlsSignature2020" proof
    Then "Max" checks the history of events "request-received,request-received,presentation-sent,presentation-sent,done,done"
  @begin_with_request_presentation_bbs_v3
  Scenario: The Verifier begins with a request presentation v3 (BBS+)
    Given "Christopher" exchange DIDs V2 with "Matthew"
    Then "Christopher" sends a request presentation v3 with presentation definition to the "Matthew"
    And "Matthew" accepts a request v3 and sends credentials with BBS to the "Christopher" and proof "BbsBlsSignature2020"
    And "Christopher" accepts a presentation with name "bbs-license"
    And "Christopher" checks that presentation is being stored under "bbs-license" name and has "BbsBlsSignature2020" proof
    Then "Matthew" checks the history of events "request-received,request-received,presentation-sent,presentation-sent,done,done"
  @begin_with_request_presentation_default_sign_bbs
  Scenario: The Verifier begins with a request presentation (default sign with BBS+)
    Given "Jennifer" exchange DIDs with "John"
    Then "Jennifer" sends a request presentation with presentation definition to the "John"
    And "John" accepts a request and sends credentials with BBS to the "Jennifer" and proof "default"
    And "Jennifer" accepts a presentation with name "bbs-license"
    And "Jennifer" checks that presentation is being stored under "bbs-license" name and has "BbsBlsSignature2020" proof
    Then "John" checks the history of events "request-received,request-received,presentation-sent,presentation-sent,done,done"
  @begin_with_request_presentation_default_sign_bbs_v3
  Scenario: The Verifier begins with a request presentation v3 (default sign with BBS+)
    Given "Scott" exchange DIDs V2 with "Patrick"
    Then "Scott" sends a request presentation v3 with presentation definition to the "Patrick"
    And "Patrick" accepts a request v3 and sends credentials with BBS to the "Scott" and proof "default"
    And "Scott" accepts a presentation with name "bbs-license"
    And "Scott" checks that presentation is being stored under "bbs-license" name and has "BbsBlsSignature2020" proof
    Then "Patrick" checks the history of events "request-received,request-received,presentation-sent,presentation-sent,done,done"
  @decline_presentation
  Scenario: The Verifier declines presentation
    Given "Thomas" exchange DIDs with "Paul"
    Then "Thomas" sends a request presentation to the "Paul"
    And "Paul" accepts a request and sends a presentation to the "Thomas"
    And "Thomas" declines presentation
    Then "Paul" receives problem report message (Present Proof)
    Then "Paul" checks the history of events "request-received,request-received,presentation-sent,presentation-sent,abandoned,abandoned"
    And "Thomas" checks the history of events "request-sent,request-sent,abandoned,abandoned"
  @decline_presentation_v3
  Scenario: The Verifier declines presentation v3
    Given "Dennis" exchange DIDs V2 with "Nathan"
    Then "Dennis" sends a request presentation v3 to the "Nathan"
    And "Nathan" accepts a request and sends a presentation v3 to the "Dennis"
    And "Dennis" declines presentation
    Then "Nathan" receives problem report message (Present Proof)
    Then "Nathan" checks the history of events "request-received,request-received,presentation-sent,presentation-sent,abandoned,abandoned"
    And "Dennis" checks the history of events "request-sent,request-sent,abandoned,abandoned"
  @decline_request_presentation
  Scenario: The Prover declines a request presentation
    Given "Liam" exchange DIDs with "Samuel"
    Then "Liam" sends a request presentation to the "Samuel"
    And "Samuel" declines a request presentation
    Then "Liam" receives problem report message (Present Proof)
    Then "Samuel" checks the history of events "abandoned,abandoned"
    And "Liam" checks the history of events "request-sent,request-sent,abandoned,abandoned"
  @decline_request_presentation_v3
  Scenario: The Prover declines a request presentation v3
    Given "Tyler" exchange DIDs V2 with "Adam"
    Then "Tyler" sends a request presentation v3 to the "Adam"
    And "Adam" declines a request presentation
    Then "Tyler" receives problem report message (Present Proof)
    Then "Adam" checks the history of events "abandoned,abandoned"
    And "Tyler" checks the history of events "request-sent,request-sent,abandoned,abandoned"
  @begin_with_propose_presentation
  Scenario: The Prover begins with a proposal
    Given "Carol" exchange DIDs with "Andrew"
    Then "Carol" sends a propose presentation to the "Andrew"
    And "Andrew" accepts a proposal and sends a request to the Prover
    And "Carol" accepts a request and sends a presentation to the "Andrew"
    And "Andrew" accepts a presentation with name "passport"
    And "Andrew" checks that presentation is being stored under "passport" name
    Then "Carol" checks the history of events "proposal-sent,proposal-sent,request-received,request-received,presentation-sent,presentation-sent,done,done"
  @begin_with_propose_presentation_v3
  Scenario: The Prover begins with a proposal v3
    Given "Douglas" exchange DIDs V2 with "Peter"
    Then "Douglas" sends a propose presentation v3 to the "Peter"
    And "Peter" accepts a proposal and sends a request v3 to the Prover
    And "Douglas" accepts a request and sends a presentation v3 to the "Peter"
    And "Peter" accepts a presentation with name "passport"
    And "Peter" checks that presentation is being stored under "passport" name
    Then "Douglas" checks the history of events "proposal-sent,proposal-sent,request-received,request-received,presentation-sent,presentation-sent,done,done"
  @decline_propose_presentation
  Scenario: The Verifier declines a propose presentation
    Given "Michael" exchange DIDs with "David"
    Then "Michael" sends a propose presentation to the "David"
    And "David" declines a propose presentation
    Then "Michael" receives problem report message (Present Proof)
    Then "Michael" checks the history of events "proposal-sent,proposal-sent,abandoned,abandoned"
    And "David" checks the history of events "abandoned,abandoned"
  @decline_propose_presentation_v3
  Scenario: The Verifier declines a propose presentation v3
    Given "Harold" exchange DIDs V2 with "Roger"
    Then "Harold" sends a propose presentation v3 to the "Roger"
    And "Roger" declines a propose presentation
    Then "Harold" receives problem report message (Present Proof)
    Then "Harold" checks the history of events "proposal-sent,proposal-sent,abandoned,abandoned"
    And "Roger" checks the history of events "abandoned,abandoned"
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
  @begin_with_request_presentation_negotiation_v3
  Scenario: The Verifier begins with a request presentation v3 (negotiation)
    Given "Sean" exchange DIDs V2 with "Joe"
    Then "Sean" sends a request presentation v3 to the "Joe"
    Then "Joe" negotiates about the request presentation v3 with a proposal
    And "Sean" accepts a proposal and sends a request v3 to the Prover
    And "Joe" accepts a request and sends a presentation v3 to the "Sean"
    And "Sean" accepts a presentation with name "passport"
    And "Sean" checks that presentation is being stored under "passport" name
    Then "Joe" checks the history of events "request-received,request-received,proposal-sent,proposal-sent,request-received,request-received,presentation-sent,presentation-sent,done,done"
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
  @begin_with_propose_presentation_negotiation_v3
  Scenario: The Prover begins with a proposal v3 (negotiation)
    Given "Arthur" exchange DIDs V2 with "Logan"
    Then "Arthur" sends a propose presentation v3 to the "Logan"
    And "Logan" accepts a proposal and sends a request v3 to the Prover
    Then "Arthur" negotiates about the request presentation v3 with a proposal
    And "Logan" accepts a proposal and sends a request v3 to the Prover
    And "Arthur" accepts a request and sends a presentation v3 to the "Logan"
    And "Logan" accepts a presentation with name "bachelors degree"
    And "Logan" checks that presentation is being stored under "bachelors degree" name
    Then "Arthur" checks the history of events "proposal-sent,proposal-sent,request-received,request-received,proposal-sent,proposal-sent,request-received,request-received,presentation-sent,presentation-sent,done,done"
  @share_redirect_presentation_ack
  Scenario: The Verifier begins with a request presentation (Web Redirect)
    Given "Dan" exchange DIDs with "Tracy"
    Then "Dan" sends a request presentation to the "Tracy"
    And "Tracy" accepts a request and sends a presentation to the "Dan"
    And "Dan" accepts a presentation with name "license" and requests redirect to "http://example.com/success"
    And "Dan" checks that presentation is being stored under "license" name
    Then "Tracy" receives present proof event "done" with status "OK" and redirect "http://example.com/success"
  @share_redirect_presentation_problem_report_1
  Scenario: The Verifier declines presentation (Web Redirect)
    Given "Tim" exchange DIDs with "Wendy"
    Then "Tim" sends a request presentation to the "Wendy"
    And "Wendy" accepts a request and sends a presentation to the "Tim"
    And "Tim" declines presentation and requests redirect to "http://example.com/error"
    Then "Wendy" receives problem report message (Present Proof)
    Then "Wendy" receives present proof event "abandoned" with status "FAIL" and redirect "http://example.com/error"
  @share_redirect_presentation_problem_report_2
  Scenario: The Verifier declines presentation (Web Redirect)
    Given "Tiana" exchange DIDs with "Gracia"
    Then "Gracia" sends a propose presentation to the "Tiana"
    And "Tiana" declines a propose presentation and requests redirect to "http://example.com/error"
    Then "Gracia" receives problem report message (Present Proof)
    Then "Gracia" receives present proof event "abandoned" with status "FAIL" and redirect "http://example.com/error"
  @ppv3_no_didex
  Scenario: The Verifier begins with a request presentation v3 without didexchange
    Given "Clarence" agent is running on "localhost" port "random" with "http" as the transport provider and "sidetree=${SIDETREE_URL},DIDCommV2" flags
     And "Florence" agent is running on "localhost" port "random" with "http" as the transport provider and "sidetree=${SIDETREE_URL},DIDCommV2" flags
    Given "Clarence" creates public DID for did method "sidetree"
     And "Florence" creates public DID for did method "sidetree"
    Then "Clarence" waits for public did to become available in sidetree for up to 10 seconds
    And "Florence" waits for public did to become available in sidetree for up to 10 seconds
    And "Clarence" and "Florence" have a DIDComm v2 connection
    Then "Clarence" sends a request presentation v3 to the "Florence"
    And "Florence" accepts a request and sends a presentation v3 to the "Clarence"
    And "Clarence" accepts a presentation with name "license"
    And "Clarence" checks that presentation is being stored under "license" name
    Then "Florence" checks the history of events "request-received,request-received,presentation-sent,presentation-sent,done,done"
