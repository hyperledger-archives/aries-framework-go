#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0036-issue-credential

@all
@controller
@issue_credential_controller
Feature: Issue Credential using controller API

  Scenario: The Holder begins with a request
    Given "Driver" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
      And "Institution" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
      And "Driver" has established connection with "Institution" through IssueCredential controller

    When  "Driver" requests credential from "Institution" through IssueCredential controller
      And "Institution" accepts request and sends credential to the Holder through IssueCredential controller
      And "Driver" accepts credential with name "license" through IssueCredential controller

    Then  "Driver" checks that issued credential is being stored under "license" name

  Scenario: The Issuer begins with an offer
    Given "Citizen" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
      And "Government" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
      And "Citizen" has established connection with "Government" through IssueCredential controller

    When  "Government" sends an offer to the "Citizen" through IssueCredential controller
      And "Citizen" accepts an offer and sends a request to the Issuer through IssueCredential controller
      And "Government" accepts request and sends credential to the Holder through IssueCredential controller
      And "Citizen" accepts credential with name "passport" through IssueCredential controller

    Then  "Citizen" checks that issued credential is being stored under "passport" name

  Scenario: The Holder begins with a proposal
    Given "Student" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
      And "University" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
      And "Student" has established connection with "University" through IssueCredential controller

    When  "Student" sends proposal credential to the "University" through IssueCredential controller
      And "University" accepts a proposal and sends an offer to the Holder through IssueCredential controller
      And "Student" accepts an offer and sends a request to the Issuer through IssueCredential controller
      And "University" accepts request and sends credential to the Holder through IssueCredential controller
      And "Student" accepts credential with name "degree" through IssueCredential controller

    Then  "Student" checks that issued credential is being stored under "degree" name

  Scenario: The Holder begins with a proposal (negotiation)
    Given "Graduate" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
      And "Stanford University" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
      And "Graduate" has established connection with "Stanford University" through IssueCredential controller

    When  "Graduate" sends proposal credential to the "Stanford University" through IssueCredential controller
      And "Stanford University" accepts a proposal and sends an offer to the Holder through IssueCredential controller
      And "Graduate" does not like the offer and sends a new proposal to the Issuer through IssueCredential controller
      And "Stanford University" accepts a proposal and sends an offer to the Holder through IssueCredential controller
      And "Graduate" accepts an offer and sends a request to the Issuer through IssueCredential controller
      And "Stanford University" accepts request and sends credential to the Holder through IssueCredential controller
      And "Graduate" accepts credential with name "bachelors degree" through IssueCredential controller

    Then  "Graduate" checks that issued credential is being stored under "bachelors degree" name
