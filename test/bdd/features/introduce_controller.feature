#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0028-introduce

@all
@controller
@introduce_controller
Feature: Introduce using controller API
  @controller_skip_proposal
  Scenario: Alice has Carol's public out-of-band invitation
    Given "Alice" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Bob" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
    And "Carol" agent is running on "localhost" port "11011" with controller "https://localhost:11012"
    Then "Bob,Carol" has established connection with "Alice" through the controller

    And   "Alice" sends introduce proposal to the "Bob" with "Carol" out-of-band invitation through the controller
    When   "Bob" wants to know "Carol" and sends introduce response with approve through the controller
    Then  "Bob" has did exchange connection with "Carol" through the controller
  @controller_skip_proposal_with_request
  Scenario: Jacob has a Carol's public out-of-band invitation. The protocol starts with introduce request.
    Given "Jacob" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Emma" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
    And "Carol" agent is running on "localhost" port "11011" with controller "https://localhost:11012"
    Then "Emma,Carol" has established connection with "Jacob" through the controller

    And   "Emma" sends introduce request to the "Jacob" asking about "Carol" through the controller
    And   "Jacob" sends introduce proposal back to the requester with public out-of-band invitation through the controller
    When   "Emma" wants to know "Carol" and sends introduce response with approve through the controller
    And  "Emma" has did exchange connection with "Carol" through the controller
  @controller_proposal
  Scenario: William sends a response with approve and an out-of-band invitation.
    Given "William" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Olivia" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
    And "Alice" agent is running on "localhost" port "11011" with controller "https://localhost:11012"
    Then "William,Olivia" has established connection with "Alice" through the controller

    When   "Alice" sends introduce proposal to the "William" and "Olivia" through the controller
    And   "William" wants to know "Olivia" and sends introduce response with approve and provides an out-of-band invitation through the controller
    And   "Olivia" wants to know "William" and sends introduce response with approve through the controller
    Then  "Olivia" has did exchange connection with "William" through the controller
  @controller_proposal_with_request
  Scenario: Mason sends a response with approve and an out-of-band invitation. The protocol starts with introduce request
    Given "Mason" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Sophia" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
    And "Alice" agent is running on "localhost" port "11011" with controller "https://localhost:11012"
    Then "Mason,Sophia" has established connection with "Alice" through the controller

    When   "Mason" sends introduce request to the "Alice" asking about "Sophia" through the controller
    And   "Alice" sends introduce proposal back to the "Mason" and requested introduce through the controller
    And   "Mason" wants to know "Sophia" and sends introduce response with approve and provides an out-of-band invitation through the controller
    And   "Sophia" wants to know "Mason" and sends introduce response with approve through the controller
    Then  "Sophia" has did exchange connection with "Mason" through the controller
