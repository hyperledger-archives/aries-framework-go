#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

# Reference : https://github.com/hyperledger/aries-rfcs/blob/master/features/0434-outofband/README.md

@controller
@outofband
@outofband_controller_sdk
Feature: Out-Of-Band protocol (REST API)

  Background:
    Given "Alice" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    And "Bob" agent is running on "localhost" port "9081" with controller "https://localhost:9082"

  Scenario: New connection after Alice sends an ouf-of-band invitation to Bob
    Given "Alice" constructs an out-of-band invitation (controller)
    When "Alice" sends the invitation to "Bob" through an out-of-band channel (controller)
    And "Bob" accepts the invitation and connects with "Alice" (controller)
    Then "Alice" and "Bob" have a connection (controller)
