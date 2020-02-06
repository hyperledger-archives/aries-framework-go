#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@aries_router
Feature: DIDComm Transport between two Agents through DIDComm Routers

  # https://wiki.hyperledger.org/display/ARIES/DIDComm+MediatorRouter
  Scenario: Decentralized Identifier(DID) Exchange between two Edge Agents(without Inbound) through Routers
    # DID Exchange between Alice and her Router
    Given "Alice-Router" agent is running on "localhost" port "random" with "websocket" as the transport provider
      And   "Alice-Router" creates did exchange client
      And   "Alice-Router" registers to receive notification for post state event "completed"

    Given "Alice" edge agent is running with "websocket" as the outbound transport provider and "all" as the transport return route option
      And   "Alice" creates did exchange client
      And   "Alice" registers to receive notification for post state event "completed"

    When   "Alice-Router" creates invitation
      And   "Alice-Router" validates that invitation service endpoint of type "ws"
      And   "Alice" receives invitation from "Alice-Router"
      And   "Alice" approves invitation request
      And   "Alice-Router" approves did exchange request
      And   "Alice-Router" waits for post state event "completed"
      And   "Alice" waits for post state event "completed"

    Then   "Alice-Router" retrieves connection record and validates that connection state is "completed"
      And   "Alice" retrieves connection record and validates that connection state is "completed"
      And   "Alice" saves connectionID to variable "xyz"

     # DID Exchange between Bob and his Router
    Given "Bob" edge agent is running with "websocket" as the outbound transport provider and "all" as the transport return route option
      And   "Bob" creates did exchange client

    Given "Bob-Router" agent is running on "localhost" port "random" with "websocket" as the transport provider
      And   "Bob-Router" creates did exchange client
      And   "Bob-Router" registers to receive notification for post state event "completed"
      And   "Bob" registers to receive notification for post state event "completed"

    When   "Bob-Router" creates invitation
      And   "Bob-Router" validates that invitation service endpoint of type "ws"
      And   "Bob" receives invitation from "Bob-Router"
      And   "Bob" approves invitation request
      And   "Bob-Router" approves did exchange request
      And   "Bob-Router" waits for post state event "completed"
      And   "Bob" waits for post state event "completed"

    Then   "Bob-Router" retrieves connection record and validates that connection state is "completed"
      And   "Bob" retrieves connection record and validates that connection state is "completed"
      And   "Bob" saves connectionID to variable "abc"

       # Alice registers her Router
      And   "Alice" creates a route exchange client
      And   "Alice" sets "xyz" as the router

       # Bob registers his Router
      And   "Bob" creates a route exchange client
      And   "Bob" sets "abc" as the router

     # DIDExchange between Alice and Bob through routers
    When   "Alice" creates invitation
      And   "Alice" validates that invitation service endpoint of type "ws"
      And   "Bob" receives invitation from "Alice"
      And   "Bob" approves invitation request
      And   "Alice" approves did exchange request
      And   "Alice" waits for post state event "completed"
      And   "Bob" waits for post state event "completed"

    Then   "Alice" retrieves connection record and validates that connection state is "completed"
      And   "Bob" retrieves connection record and validates that connection state is "completed"

  Scenario: Decentralized Identifier(DID) Exchange between two Edge Agents through Routers
    # DID Exchange between Alice and her Router
    Given "Alice-Router" agent is running on "localhost" port "random" with "http" as the transport provider
      And   "Alice-Router" creates did exchange client
      And   "Alice-Router" registers to receive notification for post state event "completed"

    Given "Alice" agent is running on "localhost" port "random" with "http" as the transport provider
      And   "Alice" creates did exchange client
      And   "Alice" registers to receive notification for post state event "completed"

    When   "Alice-Router" creates invitation
      And   "Alice-Router" validates that invitation service endpoint of type "http"
      And   "Alice" receives invitation from "Alice-Router"
      And   "Alice" approves invitation request
      And   "Alice-Router" approves did exchange request
      And   "Alice-Router" waits for post state event "completed"
      And   "Alice" waits for post state event "completed"

    Then   "Alice-Router" retrieves connection record and validates that connection state is "completed"
      And   "Alice" retrieves connection record and validates that connection state is "completed"
      And   "Alice" saves connectionID to variable "xyz"

     # DID Exchange between Bob and his Router
    Given "Bob" agent is running on "localhost" port "random" with "http" as the transport provider
      And   "Bob" creates did exchange client

    Given "Bob-Router" agent is running on "localhost" port "random" with "http" as the transport provider
      And   "Bob-Router" creates did exchange client
      And   "Bob-Router" registers to receive notification for post state event "completed"
      And   "Bob" registers to receive notification for post state event "completed"

    When   "Bob-Router" creates invitation
      And   "Bob-Router" validates that invitation service endpoint of type "http"
      And   "Bob" receives invitation from "Bob-Router"
      And   "Bob" approves invitation request
      And   "Bob-Router" approves did exchange request
      And   "Bob-Router" waits for post state event "completed"
      And   "Bob" waits for post state event "completed"

    Then   "Bob-Router" retrieves connection record and validates that connection state is "completed"
      And   "Bob" retrieves connection record and validates that connection state is "completed"
      And   "Bob" saves connectionID to variable "abc"

       # Alice registers her Router
      And   "Alice" creates a route exchange client
      And   "Alice" sets "xyz" as the router

       # Bob registers his Router
      And   "Bob" creates a route exchange client
      And   "Bob" sets "abc" as the router

     # DIDExchange between Alice and Bob through routers
    When   "Alice" creates invitation
      And   "Alice" validates that invitation service endpoint of type "http"
      And   "Bob" receives invitation from "Alice"
      And   "Bob" approves invitation request
      And   "Alice" approves did exchange request
      And   "Alice" waits for post state event "completed"
      And   "Bob" waits for post state event "completed"

    Then   "Alice" retrieves connection record and validates that connection state is "completed"
      And   "Bob" retrieves connection record and validates that connection state is "completed"

  # https://wiki.hyperledger.org/display/ARIES/DIDComm+MediatorRouter
  Scenario: Decentralized Identifier(DID) Exchange between two Edge Agents(without Inbound) through Routers(HTTP/WS)
    # DID Exchange between Alice and her Router
    Given "Alice-Router" agent is running on "localhost,localhost" port "random,random" with "http,websocket" as the transport provider
      And   "Alice-Router" creates did exchange client
      And   "Alice-Router" registers to receive notification for post state event "completed"

    Given "Alice" edge agent is running with "http,websocket" as the outbound transport provider and "all" as the transport return route option
      And   "Alice" creates did exchange client
      And   "Alice" registers to receive notification for post state event "completed"

    When   "Alice-Router" creates invitation
      And   "Alice-Router" validates that invitation service endpoint of type "ws"
      And   "Alice" receives invitation from "Alice-Router"
      And   "Alice" approves invitation request
      And   "Alice-Router" approves did exchange request
      And   "Alice-Router" waits for post state event "completed"
      And   "Alice" waits for post state event "completed"

    Then   "Alice-Router" retrieves connection record and validates that connection state is "completed"
      And   "Alice" retrieves connection record and validates that connection state is "completed"
      And   "Alice" saves connectionID to variable "xyz"

     # DID Exchange between Bob and his Router
    Given "Bob" edge agent is running with "http,websocket" as the outbound transport provider and "all" as the transport return route option
      And   "Bob" creates did exchange client

    Given "Bob-Router" agent is running on "localhost,localhost" port "random,random" with "http,websocket" as the transport provider
      And   "Bob-Router" creates did exchange client
      And   "Bob-Router" registers to receive notification for post state event "completed"
      And   "Bob" registers to receive notification for post state event "completed"

    When   "Bob-Router" creates invitation
      And   "Bob-Router" validates that invitation service endpoint of type "ws"
      And   "Bob" receives invitation from "Bob-Router"
      And   "Bob" approves invitation request
      And   "Bob-Router" approves did exchange request
      And   "Bob-Router" waits for post state event "completed"
      And   "Bob" waits for post state event "completed"

    Then   "Bob-Router" retrieves connection record and validates that connection state is "completed"
      And   "Bob" retrieves connection record and validates that connection state is "completed"
      And   "Bob" saves connectionID to variable "abc"

       # Alice registers her Router
      And   "Alice" creates a route exchange client
      And   "Alice" sets "xyz" as the router

       # Bob registers his Router
      And   "Bob" creates a route exchange client
      And   "Bob" sets "abc" as the router

     # DIDExchange between Alice and Bob through routers
    When   "Alice" creates invitation
      And   "Alice" validates that invitation service endpoint of type "http"
      And   "Bob" receives invitation from "Alice"
      And   "Bob" approves invitation request
      And   "Alice" approves did exchange request
      And   "Alice" waits for post state event "completed"
      And   "Bob" waits for post state event "completed"

    Then   "Alice" retrieves connection record and validates that connection state is "completed"
      And   "Bob" retrieves connection record and validates that connection state is "completed"
