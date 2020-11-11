#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@aries_conn_edge_router_agent
Feature: DIDComm between Edge Agent(without Inbound) and Router/Mediator

  Scenario: Decentralized Identifier(DID) between Edge Agent and Router/Mediator using Transport Return Route option [SDK Binding]
    Given "Alice" agent is running on "localhost" port "random" with "websocket" as the transport provider
    Then   "Alice" creates did exchange client
    And   "Alice" registers to receive notification for post state event "completed"

    Given "Bob" edge agent is running with "websocket" as the outbound transport provider and "all" as the transport return route option
    Then  "Bob" creates did exchange client
    And   "Bob" registers to receive notification for post state event "completed"

    When   "Alice" creates invitation
      And   "Bob" receives invitation from "Alice"

    Then   "Bob" approves invitation request
      And   "Alice" approves did exchange request

    Then   "Alice" waits for post state event "completed"
      And   "Bob" waits for post state event "completed"

    Then   "Alice" retrieves connection record and validates that connection state is "completed"
      And   "Bob" retrieves connection record and validates that connection state is "completed"

  @controller
  Scenario: Decentralized Identifier(DID) between Edge Agent and Router/Mediator using Transport Return Route option [REST Binding]
    Given "Carl" agent is running with controller "https://localhost:10081" and "all" as the transport return route option
    And   "Carl-Router" agent is running on "https://localhost:10091,wss://localhost:10092" with controller "https://localhost:10093"

    When   "Carl-Router" creates invitation through controller with label "carl-router-agent"
      And   "Carl" receives invitation from "Carl-Router" through controller

    Then   "Carl" approves exchange invitation through controller
    And   "Carl-Router" approves exchange request through controller

    Then   "Carl-Router" waits for post state event "completed" to web notifier
    And   "Carl" waits for post state event "completed" to web notifier

    Then   "Carl-Router" retrieves connection record through controller and validates that connection state is "completed"
    And   "Carl" retrieves connection record through controller and validates that connection state is "completed"
