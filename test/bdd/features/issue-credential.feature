
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@issue_credential
Feature: Issue credential protocol
  @begin_with_request
  Scenario: The Holder begins with a request
    Given   "Driver" exchange DIDs with "Institution"
    Then "Driver" requests credential from "Institution"
    And "Institution" accepts request and sends credential to the Holder
    And "Driver" accepts credential with name "license"
    Then "Driver" checks that credential is being stored under "license" name
  @begin_with_offer
  Scenario: The Issuer begins with an offer.
    Given   "Citizen" exchange DIDs with "Government"
    Then "Government" sends an offer to the "Citizen"
    And "Citizen" accepts an offer and sends a request to the Issuer
    And "Government" accepts request and sends credential to the Holder
    And "Citizen" accepts credential with name "passport"
    Then "Citizen" checks that credential is being stored under "passport" name
  @begin_with_proposal
  Scenario: The Holder begins with a proposal
    Given   "Student" exchange DIDs with "University"
    Then "Student" sends proposal credential to the "University"
    And "University" accepts a proposal and sends an offer to the Holder
    And "Student" accepts an offer and sends a request to the Issuer
    And "University" accepts request and sends credential to the Holder
    And "Student" accepts credential with name "degree"
    Then "Student" checks that credential is being stored under "degree" name