#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@aries_conn_edge_router_agent
Feature: DIDComm between Edge Agent(without Inbound) and Router/Mediator

  Scenario: Decentralized Identifier(DID) between Edge Agent and Router/Mediator using Transport Return Route option
    Given "Alice" agent is running on "localhost" port "random" with "websocket" as the transport provider
    And   "Alice" creates did exchange client
    And   "Alice" registers to receive notification for post state event "completed"
    Given "Bob" edge agent is running with "websocket" as the outbound transport provider and "all" as the transport return route option
    And   "Bob" creates did exchange client
    And   "Bob" registers to receive notification for post state event "completed"
    And   "Alice" creates invitation
    And   "Bob" receives invitation from "Alice"
    And   "Bob" approves invitation request
    And   "Alice" approves did exchange request
    And   "Alice" waits for post state event "completed"
    And   "Bob" waits for post state event "completed"
    And   "Alice" retrieves connection record and validates that connection state is "completed"
    And   "Bob" retrieves connection record and validates that connection state is "completed"