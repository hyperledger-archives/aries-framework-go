
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@issue_credential
Feature: Issue credential protocol
  @begin_with_request
  Scenario: The Holder begins with a request
    Given   "Driver" exchange DIDs with "Institution"
    Then "Driver" requests credential from "Institution"
    And "Institution" accepts request and sends credential to the Holder
    And "Driver" accepts credential with name "license"
    Then "Driver" checks that credential is being stored under "license" name
  @begin_with_request_V3
  Scenario: The Holder begins with a request v3
    Given   "DriverV3" exchange DIDs V2 with "InstitutionV3"
    Then "DriverV3" requests credential V3 from "InstitutionV3"
    And "InstitutionV3" accepts request V3 and sends credential to the Holder
    And "DriverV3" accepts credential with name "license"
    Then "DriverV3" checks that credential is being stored under "license" name
  @begin_with_offer
  Scenario: The Issuer begins with an offer.
    Given   "Citizen" exchange DIDs with "Government"
    Then "Government" sends an offer to the "Citizen"
    And "Citizen" accepts an offer and sends a request to the Issuer
    And "Government" accepts request and sends credential to the Holder
    And "Citizen" accepts credential with name "passport"
    Then "Citizen" checks that credential is being stored under "passport" name
  @begin_with_offer_V3
  Scenario: The Issuer begins with an offer v3.
    Given "CitizenV3" exchange DIDs V2 with "GovernmentV3"
    Then "GovernmentV3" sends an offer V3 to the "CitizenV3"
    And "CitizenV3" accepts an offer and sends a request to the Issuer
    And "GovernmentV3" accepts request V3 and sends credential to the Holder
    And "CitizenV3" accepts credential with name "passport"
    Then "CitizenV3" checks that credential is being stored under "passport" name
  @begin_with_proposal
  Scenario: The Holder begins with a proposal
    Given   "Student" exchange DIDs with "University"
    Then "Student" sends proposal credential to the "University"
    And "University" accepts a proposal and sends an offer to the Holder
    And "Student" accepts an offer and sends a request to the Issuer
    And "University" accepts request and sends credential to the Holder
    And "Student" accepts credential with name "degree"
    Then "Student" checks that credential is being stored under "degree" name
  @begin_with_proposal_V3
  Scenario: The Holder begins with a proposal v3
    Given "StudentV3" exchange DIDs V2 with "UniversityV3"
    Then "StudentV3" sends proposal credential V3 to the "UniversityV3"
    And "UniversityV3" accepts a proposal V3 and sends an offer to the Holder
    And "StudentV3" accepts an offer and sends a request to the Issuer
    And "UniversityV3" accepts request V3 and sends credential to the Holder
    And "StudentV3" accepts credential with name "degree"
    Then "StudentV3" checks that credential is being stored under "degree" name
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
  @negotiation_V3
  Scenario: The Holder begins with a proposal (negotiation)
    Given "GraduateV3" exchange DIDs V2 with "Stanford UniversityV3"
    Then "GraduateV3" sends proposal credential V3 to the "Stanford UniversityV3"
    And "Stanford UniversityV3" accepts a proposal V3 and sends an offer to the Holder
    Then "GraduateV3" does not like the offer V3 and sends a new proposal to the Issuer
    And "Stanford UniversityV3" accepts a proposal V3 and sends an offer to the Holder
    And "GraduateV3" accepts an offer and sends a request to the Issuer
    And "Stanford UniversityV3" accepts request V3 and sends credential to the Holder
    And "GraduateV3" accepts credential with name "bachelors degree"
    Then "GraduateV3" checks that credential is being stored under "bachelors degree" name
    And "GraduateV3" waits for state "done"
    And "Stanford UniversityV3" waits for state "done"
  @decline_request
  Scenario: The Holder begins with a request and the Issuer declines it
    Given   "Alice" exchange DIDs with "Bank"
    Then "Alice" requests credential from "Bank"
    And "Bank" declines a request
    Then "Alice" receives problem report message (Issue Credential)
    Then "Alice" waits for state "abandoning"
  @decline_request_V3
  Scenario: The Holder begins with a request and the Issuer declines it
    Given "AliceV3" exchange DIDs V2 with "BankV3"
    Then "AliceV3" requests credential V3 from "BankV3"
    And "BankV3" declines a request
    Then "AliceV3" receives problem report message (Issue Credential)
    Then "AliceV3" waits for state "abandoning"
  @decline_proposal
  Scenario: The Holder begins with a proposal and the Issuer declines it
    Given   "Bob" exchange DIDs with "Authority"
    Then "Bob" sends proposal credential to the "Authority"
    And "Authority" declines a proposal
    Then "Bob" receives problem report message (Issue Credential)
    Then "Bob" waits for state "abandoning"
  @decline_proposal_V3
  Scenario: The Holder begins with a proposal V3 and the Issuer declines it
    Given "BobV3" exchange DIDs V2 with "AuthorityV3"
    Then "BobV3" sends proposal credential V3 to the "AuthorityV3"
    And "AuthorityV3" declines a proposal
    Then "BobV3" receives problem report message (Issue Credential)
    Then "BobV3" waits for state "abandoning"
  @decline_offer
  Scenario: The Issuer begins with an offer and the Holder declines it
    Given   "Carol" exchange DIDs with "School"
    Then "School" sends an offer to the "Carol"
    And "Carol" declines an offer
    Then "School" receives problem report message (Issue Credential)
    Then "School" waits for state "abandoning"
  @decline_offer_V3
  Scenario: The Issuer begins with an offer V3 and the Holder declines it
    Given "SchoolV3" exchange DIDs V2 with "CarolV3"
    Then "SchoolV3" sends an offer V3 to the "CarolV3"
    And "CarolV3" declines an offer
    Then "SchoolV3" receives problem report message (Issue Credential)
    Then "SchoolV3" waits for state "abandoning"
  @decline_credential
  Scenario: The Holder begins with a request and the Holder declines the credential
    Given   "Tom" exchange DIDs with "eSchool"
    Then "Tom" requests credential from "eSchool"
    And "eSchool" accepts request and sends credential to the Holder
    And "Tom" declines the credential
    Then "eSchool" receives problem report message (Issue Credential)
    Then "eSchool" waits for state "abandoning"
  @decline_credential_V3
  Scenario: The Holder begins with a request V3 and the Holder declines the credential
    Given "TomV3" exchange DIDs V2 with "eSchoolV3"
    Then "TomV3" requests credential V3 from "eSchoolV3"
    And "eSchoolV3" accepts request V3 and sends credential to the Holder
    And "TomV3" declines the credential
    Then "eSchoolV3" receives problem report message (Issue Credential)
    Then "eSchoolV3" waits for state "abandoning"
  @begin_with_proposal_ok_webredirect_flow @issue_credential_redirect
  Scenario: The Holder begins with a proposal and receives offer credential message with redirect info
    Given "StudentR" exchange DIDs with "UniversityR"
    Then "StudentR" sends proposal credential to the "UniversityR"
    And "UniversityR" accepts a proposal and sends an offer to the Holder
    And "StudentR" accepts an offer and sends a request to the Issuer
    And "UniversityR" accepts request and sends credential to the Holder and requests redirect to "http://example.com/success"
    And "StudentR" accepts credential but skips agent storage
    Then "StudentR" receives issue credential event "done" with status "OK" and redirect "http://example.com/success"
  @decline_proposal_fail_webredirect_flow @issue_credential_redirect
  Scenario: The Holder begins with a proposal and the Issuer declines it with redirect info
    Given "BobR" exchange DIDs with "AuthorityR"
    Then "BobR" sends proposal credential to the "AuthorityR"
    And "AuthorityR" declines a proposal and requests redirect to "http://example.com/error1"
    Then "BobR" receives problem report message (Issue Credential)
    And "BobR" receives issue credential event "abandoning" with status "FAIL" and redirect "http://example.com/error1"
  @decline_request_fail_webredirect_flow @issue_credential_redirect
  Scenario: The Holder begins with a request and the Issuer declines it with redirect info
    Given "AliceR" exchange DIDs with "BankR"
    Then "AliceR" requests credential from "BankR"
    And "BankR" declines a request and requests redirect to "http://example.com/error2"
    Then "AliceR" receives problem report message (Issue Credential)
    And "AliceR" receives issue credential event "abandoning" with status "FAIL" and redirect "http://example.com/error2"
