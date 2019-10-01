#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange

@all
Feature: Decentralized Identifier(DID) exchange between the agents

  @didexchange_e2e
  Scenario: did exchange e2e flow
    Given "Alice" agent is running on "localhost" port "random"
    Given "Bob" agent is running on "localhost" port "random"
    And   "Alice" creates invitation
    And   "Bob" receives invitation from "Alice"

