#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0036-issue-credential

@controller
@issue_credential_controller
Feature: Issue Credential using controller API

  @issue_credential_controller_begin_with_request
  Scenario: The Holder begins with a request
    Given "Driver" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Institution" agent is running on "localhost" port "11011" with controller "https://localhost:11012"
    And "Driver" has established connection with "Institution" through IssueCredential controller

    When  "Driver" requests credential from "Institution" through IssueCredential controller
    And "Institution" accepts request and sends credential to the Holder through IssueCredential controller
    And "Driver" accepts credential with name "license" through IssueCredential controller

    Then  "Driver" checks that issued credential is being stored under "license" name

  @issue_credential_controller_begin_with_request_V3
  Scenario: The Holder begins with a request v3
    Given "DriverV3" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "InstitutionV3" agent is running on "localhost" port "11011" with controller "https://localhost:11012"
    And "DriverV3" has established DIDComm V2 connection with "InstitutionV3" through IssueCredential controller

    When "DriverV3" requests credential V3 from "InstitutionV3" through IssueCredential controller
    And "InstitutionV3" accepts request V3 and sends credential to the Holder through IssueCredential controller
    And "DriverV3" accepts credential with name "licenseV3" through IssueCredential controller

    Then  "DriverV3" checks that issued credential is being stored under "licenseV3" name

  @issue_credential_controller_begin_with_offer
  Scenario: The Issuer begins with an offer
    Given "Citizen" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
      And "Government" agent is running on "localhost" port "11011" with controller "https://localhost:11012"
      And "Citizen" has established connection with "Government" through IssueCredential controller

    When  "Government" sends an offer to the "Citizen" through IssueCredential controller
      And "Citizen" accepts an offer and sends a request to the Issuer through IssueCredential controller
      And "Government" accepts request and sends credential to the Holder through IssueCredential controller
      And "Citizen" accepts credential with name "passport" through IssueCredential controller

    Then  "Citizen" checks that issued credential is being stored under "passport" name

  @issue_credential_controller_begin_with_offer_V3
  Scenario: The Issuer begins with an offer v3
    Given "CitizenV3" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "GovernmentV3" agent is running on "localhost" port "11011" with controller "https://localhost:11012"
    And "CitizenV3" has established DIDComm V2 connection with "GovernmentV3" through IssueCredential controller

    When  "GovernmentV3" sends an offer V3 to the "CitizenV3" through IssueCredential controller
    And "CitizenV3" accepts an offer and sends a request to the Issuer through IssueCredential controller
    And "GovernmentV3" accepts request V3 and sends credential to the Holder through IssueCredential controller
    And "CitizenV3" accepts credential with name "passportV3" through IssueCredential controller

    Then  "CitizenV3" checks that issued credential is being stored under "passportV3" name

  @issue_credential_controller_begin_with_proposal
  Scenario: The Holder begins with a proposal
    Given "Student" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
      And "University" agent is running on "localhost" port "11011" with controller "https://localhost:11012"
      And "Student" has established connection with "University" through IssueCredential controller

    When  "Student" sends proposal credential to the "University" through IssueCredential controller
      And "University" accepts a proposal and sends an offer to the Holder through IssueCredential controller
      And "Student" accepts an offer and sends a request to the Issuer through IssueCredential controller
      And "University" accepts request and sends credential to the Holder through IssueCredential controller
      And "Student" accepts credential with name "degree" through IssueCredential controller

    Then  "Student" checks that issued credential is being stored under "degree" name

  @issue_credential_controller_begin_with_proposal_V3
  Scenario: The Holder begins with a proposal v3
    Given "StudentV3" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "UniversityV3" agent is running on "localhost" port "11011" with controller "https://localhost:11012"
    And "StudentV3" has established DIDComm V2 connection with "UniversityV3" through IssueCredential controller

    When  "StudentV3" sends proposal credential V3 to the "UniversityV3" through IssueCredential controller
    And "UniversityV3" accepts a proposal V3 and sends an offer to the Holder through IssueCredential controller
    And "StudentV3" accepts an offer and sends a request to the Issuer through IssueCredential controller
    And "UniversityV3" accepts request V3 and sends credential to the Holder through IssueCredential controller
    And "StudentV3" accepts credential with name "degreeV3" through IssueCredential controller

    Then  "StudentV3" checks that issued credential is being stored under "degreeV3" name


  @issue_credential_controller_negotiation
  Scenario: The Holder begins with a proposal (negotiation)
    Given "Graduate" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
      And "Stanford University" agent is running on "localhost" port "11011" with controller "https://localhost:11012"
      And "Graduate" has established connection with "Stanford University" through IssueCredential controller

    When  "Graduate" sends proposal credential to the "Stanford University" through IssueCredential controller
      And "Stanford University" accepts a proposal and sends an offer to the Holder through IssueCredential controller
      And "Graduate" does not like the offer and sends a new proposal to the Issuer through IssueCredential controller
      And "Stanford University" accepts a proposal and sends an offer to the Holder through IssueCredential controller
      And "Graduate" accepts an offer and sends a request to the Issuer through IssueCredential controller
      And "Stanford University" accepts request and sends credential to the Holder through IssueCredential controller
      And "Graduate" accepts credential with name "bachelors degree" through IssueCredential controller

    Then  "Graduate" checks that issued credential is being stored under "bachelors degree" name

  @issue_credential_controller_negotiation_V3
  Scenario: The Holder begins with a proposal v3 (negotiation)
    Given "GraduateV3" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Stanford UniversityV3" agent is running on "localhost" port "11011" with controller "https://localhost:11012"
    And "GraduateV3" has established DIDComm V2 connection with "Stanford UniversityV3" through IssueCredential controller

    When  "GraduateV3" sends proposal credential V3 to the "Stanford UniversityV3" through IssueCredential controller
    And "Stanford UniversityV3" accepts a proposal V3 and sends an offer to the Holder through IssueCredential controller
    And "GraduateV3" does not like the offer V3 and sends a new proposal to the Issuer through IssueCredential controller
    And "Stanford UniversityV3" accepts a proposal V3 and sends an offer to the Holder through IssueCredential controller
    And "GraduateV3" accepts an offer and sends a request to the Issuer through IssueCredential controller
    And "Stanford UniversityV3" accepts request V3 and sends credential to the Holder through IssueCredential controller
    And "GraduateV3" accepts credential with name "bachelors degreeV3" through IssueCredential controller

    Then  "GraduateV3" checks that issued credential is being stored under "bachelors degreeV3" name

  @issue_credential_controller_ok_webredirect_flow @issue_credential_controller_redirect
  Scenario: The Holder begins with a proposal for redirect flow
    Given "StudentR1" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "UniversityR1" agent is running on "localhost" port "11011" with controller "https://localhost:11012"
    And "StudentR1" has established connection with "UniversityR1" through IssueCredential controller

    When  "StudentR1" sends proposal credential to the "UniversityR1" through IssueCredential controller
    And "UniversityR1" accepts a proposal and sends an offer to the Holder through IssueCredential controller
    And "StudentR1" accepts an offer and sends a request to the Issuer through IssueCredential controller
    And "UniversityR1" accepts request and sends credential to the Holder with redirect "https://example.com/success" through IssueCredential controller
    And "StudentR1" accepts credential with name "degreeR" through IssueCredential controller

    Then  "StudentR1" checks that issued credential is being stored under "degreeR" name
    And "StudentR1" validates issue credential state "done" and redirect "https://example.com/success" with status "OK" through IssueCredential controller

  @issue_credential_controller_decline_request_fail_webredirect_flow @issue_credential_controller_redirect
  Scenario: The Holder begins with a proposal for decline proposal redirect flow
    Given "StudentR2" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "UniversityR2" agent is running on "localhost" port "11011" with controller "https://localhost:11012"
    And "StudentR2" has established connection with "UniversityR2" through IssueCredential controller

    When  "StudentR2" sends proposal credential to the "UniversityR2" through IssueCredential controller
    And "UniversityR2" accepts a proposal and sends an offer to the Holder through IssueCredential controller
    And "StudentR2" accepts an offer and sends a request to the Issuer through IssueCredential controller
    And "UniversityR2" declines the request and requests redirect "https://example.com/error" through IssueCredential controller

    Then  "StudentR2" accepts a problem report through IssueCredential controller
    And "StudentR2" validates issue credential state "abandoning" and redirect "https://example.com/error" with status "FAIL" through IssueCredential controller

  @issue_credential_controller_decline_proposal_fail_webredirect_flow @issue_credential_controller_redirect
  Scenario: The Holder begins with a proposal for decline request redirect flow
    Given "StudentR3" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "UniversityR3" agent is running on "localhost" port "11011" with controller "https://localhost:11012"
    And "StudentR3" has established connection with "UniversityR3" through IssueCredential controller

    When  "StudentR3" sends proposal credential to the "UniversityR3" through IssueCredential controller
    And "UniversityR3" declines the proposal and requests redirect "https://example.com/error" through IssueCredential controller

    Then "StudentR3" accepts a problem report through IssueCredential controller
    And "StudentR3" validates issue credential state "abandoning" and redirect "https://example.com/error" with status "FAIL" through IssueCredential controller
