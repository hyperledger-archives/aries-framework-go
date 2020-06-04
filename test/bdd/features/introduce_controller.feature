#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0028-introduce

@all
@introduce_controller
Feature: Introduce using controller API
  @controller_skip_proposal
  Scenario: Alice has Carol's public out-of-band request
    Given "Alice" agent is running on "localhost" port "8081" with controller "http://localhost:8082"
    And "Bob" agent is running on "localhost" port "9081" with controller "http://localhost:9082"
    And "Carol" agent is running on "localhost" port "11011" with controller "http://localhost:11012"
    Then "Bob,Carol" has established connection with "Alice" through the controller
    And   "Alice" sends introduce proposal to the "Bob" with "Carol" out-of-band request through the controller
    When   "Bob" wants to know "Carol" and sends introduce response with approve through the controller
    Then  "Bob" has did exchange connection with "Carol" through the controller
