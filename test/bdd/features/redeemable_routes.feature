#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@redeemable_routes
Feature: Redeemable routes after an introduction

  Background:
    Given "Alice" agent is running on "localhost" port "random" with "http" as the transport provider
    And "Alice" is connected to "Alice-Router" with transport "http" on "localhost" port "random"
    And "Alice" is connected to "Bob" with transport "http" on "localhost" port "random"

  Scenario: Bob redeems a route in Alice's router after an introduction
    Given "Alice" prepares an introduction proposal to "Bob" for "Alice-Router"
    And "Alice" prepares an introduction proposal to "Alice-Router" for "Bob" with the goal code "FREEROUTES"
    And "Alice" sends these proposals to "Alice-Router" and "Bob"
    When "Bob" approves
    And "Alice-Router" approves and responds with serviceEndpoint "http://routers-r-us.com" and routingKey "key1"
    And "Bob" connects with "Alice-Router" and sends the embedded route registration request
    And "Alice-Router" confirms redeemable code and approves
    Then "Bob" is granted serviceEndpoint "http://routers-r-us.com" and routingKey "key1"
