#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0036-issue-credential

@all
@issue_credential_controller
Feature: Issue credential using controller API

  Scenario: The Holder begins with a request using controller
    Given "Driver" agent is running on "localhost" port "8081" with controller "http://localhost:8082"
      And "Institution" agent is running on "localhost" port "9081" with controller "http://localhost:9082"
      And "Driver" has established connection with "Institution" using controller

    When  "Driver" requests credential from "Institution" using controller
      And "Institution" accepts request and sends credential to the Holder using controller
      And "Driver" accepts credential with name "license" using controller

    Then  "Driver" checks that issued credential is being stored under "license" name

  Scenario: The Issuer begins with an offer using controller
    Given "Citizen" agent is running on "localhost" port "8081" with controller "http://localhost:8082"
      And "Government" agent is running on "localhost" port "9081" with controller "http://localhost:9082"
      And "Citizen" has established connection with "Government" using controller

    When  "Government" sends an offer to the "Citizen" using controller
      And "Citizen" accepts an offer and sends a request to the Issuer using controller
      And "Government" accepts request and sends credential to the Holder using controller
      And "Citizen" accepts credential with name "passport" using controller

    Then  "Citizen" checks that issued credential is being stored under "passport" name

  Scenario: The Holder begins with a proposal using controller
    Given "Student" agent is running on "localhost" port "8081" with controller "http://localhost:8082"
      And "University" agent is running on "localhost" port "9081" with controller "http://localhost:9082"
      And "Student" has established connection with "University" using controller

    When  "Student" sends proposal credential to the "University" using controller
      And "University" accepts a proposal and sends an offer to the Holder using controller
      And "Student" accepts an offer and sends a request to the Issuer using controller
      And "University" accepts request and sends credential to the Holder using controller
      And "Student" accepts credential with name "degree" using controller

    Then  "Student" checks that issued credential is being stored under "degree" name

  Scenario: The Holder begins with a proposal using controller (negotiation)
    Given "Graduate" agent is running on "localhost" port "8081" with controller "http://localhost:8082"
      And "Stanford University" agent is running on "localhost" port "9081" with controller "http://localhost:9082"
      And "Graduate" has established connection with "Stanford University" using controller

    When  "Graduate" sends proposal credential to the "Stanford University" using controller
      And "Stanford University" accepts a proposal and sends an offer to the Holder using controller
      And "Graduate" does not like the offer and sends a new proposal to the Issuer using controller
      And "Stanford University" accepts a proposal and sends an offer to the Holder using controller
      And "Graduate" accepts an offer and sends a request to the Issuer using controller
      And "Stanford University" accepts request and sends credential to the Holder using controller
      And "Graduate" accepts credential with name "bachelors degree" using controller

    Then  "Graduate" checks that issued credential is being stored under "bachelors degree" name