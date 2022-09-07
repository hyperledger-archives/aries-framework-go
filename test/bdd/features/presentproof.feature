#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@presentproof
Feature: Present Proof protocol
  @begin_with_request_presentation
  Scenario Outline: The Verifier begins with a request presentation
    Given "Alice-<suffix>" exchange DIDs with "Bob-<suffix>"
    Then "Alice-<suffix>" sends a request presentation to the "Bob-<suffix>"
    And "Bob-<suffix>" accepts a request and sends a presentation to the "Alice-<suffix>" with format "<format>"
    And "Alice-<suffix>" accepts a presentation with name "license"
    And "Alice-<suffix>" checks that presentation is being stored under "license" name
    Then "Bob-<suffix>" checks the history of events "request-received,request-received,presentation-sent,presentation-sent,done,done"
    Examples:
      | suffix | format |
      | 1      | jwt    |
      | 2      | jwt_vc |
      | 3      | jwt_vp |
      | 4      | ldp    |
      | 5      | ldp_vc |
      | 6      | ldp_vp |

  @begin_with_request_presentation_v3
  Scenario Outline: The Verifier begins with a request presentation v3
    Given "Jonny-<suffix>" exchange DIDs V2 with "Robert-<suffix>"
    Then "Jonny-<suffix>" sends a request presentation v3 to the "Robert-<suffix>"
    And "Robert-<suffix>" accepts a request and sends a presentation v3 to the "Jonny-<suffix>" with format "<format>"
    And "Jonny-<suffix>" accepts a presentation with name "license"
    And "Jonny-<suffix>" checks that presentation is being stored under "license" name
    Then "Robert-<suffix>" checks the history of events "request-received,request-received,presentation-sent,presentation-sent,done,done"
    Examples:
      | suffix | format |
      | 1      | jwt    |
      | 2      | jwt_vc |
      | 3      | jwt_vp |
      | 4      | ldp    |
      | 5      | ldp_vc |
      | 6      | ldp_vp |

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
  Scenario Outline: The Verifier declines presentation
    Given "Thomas-<suffix>" exchange DIDs with "Paul-<suffix>"
    Then "Thomas-<suffix>" sends a request presentation to the "Paul-<suffix>"
    And "Paul-<suffix>" accepts a request and sends a presentation to the "Thomas-<suffix>" with format "<format>"
    And "Thomas-<suffix>" declines presentation
    Then "Paul-<suffix>" receives problem report message (Present Proof)
    Then "Paul-<suffix>" checks the history of events "request-received,request-received,presentation-sent,presentation-sent,abandoned,abandoned"
    And "Thomas-<suffix>" checks the history of events "request-sent,request-sent,abandoned,abandoned"
    Examples:
      | suffix | format |
      | 1      | jwt    |
      | 2      | jwt_vc |
      | 3      | jwt_vp |
      | 4      | ldp    |
      | 5      | ldp_vc |
      | 6      | ldp_vp |

  @decline_presentation_v3
  Scenario Outline: The Verifier declines presentation v3
    Given "Dennis-<suffix>" exchange DIDs V2 with "Nathan-<suffix>"
    Then "Dennis-<suffix>" sends a request presentation v3 to the "Nathan-<suffix>"
    And "Nathan-<suffix>" accepts a request and sends a presentation v3 to the "Dennis-<suffix>" with format "<format>"
    And "Dennis-<suffix>" declines presentation
    Then "Nathan-<suffix>" receives problem report message (Present Proof)
    Then "Nathan-<suffix>" checks the history of events "request-received,request-received,presentation-sent,presentation-sent,abandoned,abandoned"
    And "Dennis-<suffix>" checks the history of events "request-sent,request-sent,abandoned,abandoned"
    Examples:
      | suffix | format |
      | 1      | jwt    |
      | 2      | jwt_vc |
      | 3      | jwt_vp |
      | 4      | ldp    |
      | 5      | ldp_vc |
      | 6      | ldp_vp |

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
  Scenario Outline: The Prover begins with a proposal
    Given "Carol-<suffix>" exchange DIDs with "Andrew-<suffix>"
    Then "Carol-<suffix>" sends a propose presentation to the "Andrew-<suffix>"
    And "Andrew-<suffix>" accepts a proposal and sends a request to the Prover
    And "Carol-<suffix>" accepts a request and sends a presentation to the "Andrew-<suffix>" with format "<format>"
    And "Andrew-<suffix>" accepts a presentation with name "passport"
    And "Andrew-<suffix>" checks that presentation is being stored under "passport" name
    Then "Carol-<suffix>" checks the history of events "proposal-sent,proposal-sent,request-received,request-received,presentation-sent,presentation-sent,done,done"
    Examples:
      | suffix | format |
      | 1      | jwt    |
      | 2      | jwt_vc |
      | 3      | jwt_vp |
      | 4      | ldp    |
      | 5      | ldp_vc |
      | 6      | ldp_vp |

  @begin_with_propose_presentation_v3
  Scenario Outline: The Prover begins with a proposal v3
    Given "Douglas-<suffix>" exchange DIDs V2 with "Peter-<suffix>"
    Then "Douglas-<suffix>" sends a propose presentation v3 to the "Peter-<suffix>"
    And "Peter-<suffix>" accepts a proposal and sends a request v3 to the Prover
    And "Douglas-<suffix>" accepts a request and sends a presentation v3 to the "Peter-<suffix>" with format "<format>"
    And "Peter-<suffix>" accepts a presentation with name "passport"
    And "Peter-<suffix>" checks that presentation is being stored under "passport" name
    Then "Douglas-<suffix>" checks the history of events "proposal-sent,proposal-sent,request-received,request-received,presentation-sent,presentation-sent,done,done"
    Examples:
      | suffix | format |
      | 1      | jwt    |
      | 2      | jwt_vc |
      | 3      | jwt_vp |
      | 4      | ldp    |
      | 5      | ldp_vc |
      | 6      | ldp_vp |

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
  Scenario Outline: The Verifier begins with a request presentation (negotiation)
    Given "William-<suffix>" exchange DIDs with "Felix-<suffix>"
    Then "William-<suffix>" sends a request presentation to the "Felix-<suffix>"
    Then "Felix-<suffix>" negotiates about the request presentation with a proposal
    And "William-<suffix>" accepts a proposal and sends a request to the Prover
    And "Felix-<suffix>" accepts a request and sends a presentation to the "William-<suffix>" with format "<format>"
    And "William-<suffix>" accepts a presentation with name "passport"
    And "William-<suffix>" checks that presentation is being stored under "passport" name
    Then "Felix-<suffix>" checks the history of events "request-received,request-received,proposal-sent,proposal-sent,request-received,request-received,presentation-sent,presentation-sent,done,done"
    Examples:
      | suffix | format |
      | 1      | jwt    |
      | 2      | jwt_vc |
      | 3      | jwt_vp |
      | 4      | ldp    |
      | 5      | ldp_vc |
      | 6      | ldp_vp |

  @begin_with_request_presentation_negotiation_v3
  Scenario Outline: The Verifier begins with a request presentation v3 (negotiation)
    Given "Sean-<suffix>" exchange DIDs V2 with "Joe-<suffix>"
    Then "Sean-<suffix>" sends a request presentation v3 to the "Joe-<suffix>"
    Then "Joe-<suffix>" negotiates about the request presentation v3 with a proposal
    And "Sean-<suffix>" accepts a proposal and sends a request v3 to the Prover
    And "Joe-<suffix>" accepts a request and sends a presentation v3 to the "Sean-<suffix>" with format "<format>"
    And "Sean-<suffix>" accepts a presentation with name "passport"
    And "Sean-<suffix>" checks that presentation is being stored under "passport" name
    Then "Joe-<suffix>" checks the history of events "request-received,request-received,proposal-sent,proposal-sent,request-received,request-received,presentation-sent,presentation-sent,done,done"
    Examples:
      | suffix | format |
      | 1      | jwt    |
      | 2      | jwt_vc |
      | 3      | jwt_vp |
      | 4      | ldp    |
      | 5      | ldp_vc |
      | 6      | ldp_vp |

  @begin_with_propose_presentation_negotiation
  Scenario Outline: The Prover begins with a proposal (negotiation)
    Given "Jason-<suffix>" exchange DIDs with "Jesse-<suffix>"
    Then "Jason-<suffix>" sends a propose presentation to the "Jesse-<suffix>"
    And "Jesse-<suffix>" accepts a proposal and sends a request to the Prover
    Then "Jason-<suffix>" negotiates about the request presentation with a proposal
    And "Jesse-<suffix>" accepts a proposal and sends a request to the Prover
    And "Jason-<suffix>" accepts a request and sends a presentation to the "Jesse-<suffix>" with format "<format>"
    And "Jesse-<suffix>" accepts a presentation with name "bachelors degree"
    And "Jesse-<suffix>" checks that presentation is being stored under "bachelors degree" name
    Then "Jason-<suffix>" checks the history of events "proposal-sent,proposal-sent,request-received,request-received,proposal-sent,proposal-sent,request-received,request-received,presentation-sent,presentation-sent,done,done"
    Examples:
      | suffix | format |
      | 1      | jwt    |
      | 2      | jwt_vc |
      | 3      | jwt_vp |
      | 4      | ldp    |
      | 5      | ldp_vc |
      | 6      | ldp_vp |

  @begin_with_propose_presentation_negotiation_v3
  Scenario Outline: The Prover begins with a proposal v3 (negotiation)
    Given "Arthur-<suffix>" exchange DIDs V2 with "Logan-<suffix>"
    Then "Arthur-<suffix>" sends a propose presentation v3 to the "Logan-<suffix>"
    And "Logan-<suffix>" accepts a proposal and sends a request v3 to the Prover
    Then "Arthur-<suffix>" negotiates about the request presentation v3 with a proposal
    And "Logan-<suffix>" accepts a proposal and sends a request v3 to the Prover
    And "Arthur-<suffix>" accepts a request and sends a presentation v3 to the "Logan-<suffix>" with format "<format>"
    And "Logan-<suffix>" accepts a presentation with name "bachelors degree"
    And "Logan-<suffix>" checks that presentation is being stored under "bachelors degree" name
    Then "Arthur-<suffix>" checks the history of events "proposal-sent,proposal-sent,request-received,request-received,proposal-sent,proposal-sent,request-received,request-received,presentation-sent,presentation-sent,done,done"
    Examples:
      | suffix | format |
      | 1      | jwt    |
      | 2      | jwt_vc |
      | 3      | jwt_vp |
      | 4      | ldp    |
      | 5      | ldp_vc |
      | 6      | ldp_vp |

  @share_redirect_presentation_ack
  Scenario Outline: The Verifier begins with a request presentation (Web Redirect)
    Given "Dan-<suffix>" exchange DIDs with "Tracy-<suffix>"
    Then "Dan-<suffix>" sends a request presentation to the "Tracy-<suffix>"
    And "Tracy-<suffix>" accepts a request and sends a presentation to the "Dan-<suffix>" with format "<format>"
    And "Dan-<suffix>" accepts a presentation with name "license" and requests redirect to "http://example.com/success"
    And "Dan-<suffix>" checks that presentation is being stored under "license" name
    Then "Tracy-<suffix>" receives present proof event "done" with status "OK" and redirect "http://example.com/success"
    Examples:
      | suffix | format |
      | 1      | jwt    |
      | 2      | jwt_vc |
      | 3      | jwt_vp |
      | 4      | ldp    |
      | 5      | ldp_vc |
      | 6      | ldp_vp |

  @share_redirect_presentation_problem_report_1
  Scenario Outline: The Verifier declines presentation (Web Redirect)
    Given "Tim-<suffix>" exchange DIDs with "Wendy-<suffix>"
    Then "Tim-<suffix>" sends a request presentation to the "Wendy-<suffix>"
    And "Wendy-<suffix>" accepts a request and sends a presentation to the "Tim-<suffix>" with format "<format>"
    And "Tim-<suffix>" declines presentation and requests redirect to "http://example.com/error"
    Then "Wendy-<suffix>" receives problem report message (Present Proof)
    Then "Wendy-<suffix>" receives present proof event "abandoned" with status "FAIL" and redirect "http://example.com/error"
    Examples:
      | suffix | format |
      | 1      | jwt    |
      | 2      | jwt_vc |
      | 3      | jwt_vp |
      | 4      | ldp    |
      | 5      | ldp_vc |
      | 6      | ldp_vp |

  @share_redirect_presentation_problem_report_2
  Scenario: The Verifier declines presentation (Web Redirect)
    Given "Tiana" exchange DIDs with "Gracia"
    Then "Gracia" sends a propose presentation to the "Tiana"
    And "Tiana" declines a propose presentation and requests redirect to "http://example.com/error"
    Then "Gracia" receives problem report message (Present Proof)
    Then "Gracia" receives present proof event "abandoned" with status "FAIL" and redirect "http://example.com/error"
  @ppv3_no_didex
  Scenario Outline: The Verifier begins with a request presentation v3 without didexchange
    Given "Clarence-<suffix>" agent is running on "localhost" port "random" with "http" as the transport provider and "sidetree=${SIDETREE_URL},DIDCommV2" flags
     And "Florence-<suffix>" agent is running on "localhost" port "random" with "http" as the transport provider and "sidetree=${SIDETREE_URL},DIDCommV2" flags
    Given "Clarence-<suffix>" creates public DID for did method "sidetree"
     And "Florence-<suffix>" creates public DID for did method "sidetree"
    Then "Clarence-<suffix>" waits for public did to become available in sidetree for up to 10 seconds
    And "Florence-<suffix>" waits for public did to become available in sidetree for up to 10 seconds
    And "Clarence-<suffix>" and "Florence-<suffix>" have a DIDComm v2 connection
    Then "Clarence-<suffix>" sends a request presentation v3 to the "Florence-<suffix>"
    And "Florence-<suffix>" accepts a request and sends a presentation v3 to the "Clarence-<suffix>" with format "<format>"
    And "Clarence-<suffix>" accepts a presentation with name "license"
    And "Clarence-<suffix>" checks that presentation is being stored under "license" name
    Then "Florence-<suffix>" checks the history of events "request-received,request-received,presentation-sent,presentation-sent,done,done"
    Examples:
      | suffix | format |
      | 1      | jwt    |
      | 2      | jwt_vc |
      | 3      | jwt_vp |
      | 4      | ldp    |
      | 5      | ldp_vc |
      | 6      | ldp_vp |
