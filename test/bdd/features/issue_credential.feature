
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
  @negotiation
  Scenario: The Holder begins with a proposal (negotiation)
    Given   "Graduate" exchange DIDs with "Stanford University"
    Then "Graduate" sends proposal credential to the "Stanford University"
    And "Stanford University" accepts a proposal and sends an offer to the Holder
    Then "Graduate" does not like the offer and sends a new proposal to the Issuer
    And "Stanford University" accepts a proposal and sends an offer to the Holder
    And "Graduate" accepts an offer and sends a request to the Issuer
    And "Stanford University" accepts request and sends credential to the Holder
    And "Graduate" accepts credential with name "bachelors degree"
    Then "Graduate" checks that credential is being stored under "bachelors degree" name
    And "Graduate" waits for state "done"
    And "Stanford University" waits for state "done"
  @decline_request
  Scenario: The Holder begins with a request and the Issuer declines it
    Given   "Alice" exchange DIDs with "Bank"
    Then "Alice" requests credential from "Bank"
    And "Bank" declines a request
    Then "Alice" receives problem report message (Issue Credential)
    Then "Alice" waits for state "abandoning"
  @decline_proposal
  Scenario: The Holder begins with a proposal and the Issuer declines it
    Given   "Bob" exchange DIDs with "Authority"
    Then "Bob" sends proposal credential to the "Authority"
    And "Authority" declines a proposal
    Then "Bob" receives problem report message (Issue Credential)
    Then "Bob" waits for state "abandoning"
  @decline_offer
  Scenario: The Issuer begins with an offer and the Holder declines it
    Given   "Carol" exchange DIDs with "School"
    Then "School" sends an offer to the "Carol"
    And "Carol" declines an offer
    Then "School" receives problem report message (Issue Credential)
    Then "School" waits for state "abandoning"
  @decline_credential
  Scenario: The Holder begins with a request and the Holder declines the credential
    Given   "Tom" exchange DIDs with "eSchool"
    Then "Tom" requests credential from "eSchool"
    And "eSchool" accepts request and sends credential to the Holder
    And "Tom" declines the credential
    Then "eSchool" receives problem report message (Issue Credential)
    Then "eSchool" waits for state "abandoning"