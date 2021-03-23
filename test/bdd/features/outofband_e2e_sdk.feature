#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

# Reference : https://github.com/hyperledger/aries-rfcs/blob/master/features/0434-outofband/README.md

@all
@outofband_e2e_sdk
Feature: Out-Of-Band protocol

  Background:
    Given "Alice" agent is running on "localhost" port "random" with "http" as the transport provider
    And "Bob" agent is running on "localhost" port "random" with "http" as the transport provider

  Scenario: New connection after Alice sends an ouf-of-band invitation to Bob
    Given "Alice" constructs an out-of-band invitation
    When "Alice" sends the invitation to "Bob" through an out-of-band channel
    And "Bob" accepts the invitation and connects with "Alice"
    Then "Alice" and "Bob" confirm their connection is "completed"
