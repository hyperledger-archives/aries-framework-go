#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@aries_router_sdk
Feature: DIDComm Transport between two Agents through DIDComm Routers [SDK]

  # https://wiki.hyperledger.org/display/ARIES/DIDComm+MediatorRouter
  Scenario Outline: Decentralized Identifier(DID) Exchange between two Edge Agents(without Inbound) through Routers
    # DID Exchange between Alice and her Router
    Given options "<keyType>" "<keyAgreementType>" "<mediaTypeProfile>"
      And "Alice-Router" agent is running on "localhost" port "random" with "websocket" as the transport provider
      And "Alice-Router" creates a route exchange client
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
      And   "Alice-Router,Alice" waits for post state event "completed"

    Then   "Alice-Router,Alice" retrieves connection record and validates that connection state is "completed"
      And   "Alice" saves connectionID to variable "alice-router-connID"

     # DID Exchange between Bob and his Router
    Given "Bob" edge agent is running with "websocket" as the outbound transport provider and "all" as the transport return route option
      And   "Bob" creates did exchange client

    Given "Bob-Router" agent is running on "localhost" port "random" with "websocket" as the transport provider
      And "Bob-Router" creates a route exchange client
      And   "Bob-Router" creates did exchange client
      And   "Bob-Router" registers to receive notification for post state event "completed"
      And   "Bob" registers to receive notification for post state event "completed"

    When   "Bob-Router" creates invitation
      And   "Bob-Router" validates that invitation service endpoint of type "ws"
      And   "Bob" receives invitation from "Bob-Router"
      And   "Bob" approves invitation request
      And   "Bob-Router" approves did exchange request
      And   "Bob-Router,Bob" waits for post state event "completed"

    Then   "Bob-Router,Bob" retrieves connection record and validates that connection state is "completed"
      And   "Bob" saves connectionID to variable "bob-router-connID"

       # Alice registers her Router
      And   "Alice" creates a route exchange client
      And   "Alice" sets "alice-router-connID" as the router and "Alice-Router" approves
      And   "Alice" verifies that the router connection id is set to "alice-router-connID"

       # Bob registers his Router
      And   "Bob" creates a route exchange client
      And   "Bob" sets "bob-router-connID" as the router and "Bob-Router" approves
      And   "Bob" verifies that the router connection id is set to "bob-router-connID"

     # DIDExchange between Alice and Bob through routers
    When   "Alice" creates invitation with router "alice-router-connID"
      And   "Alice" validates that invitation service endpoint of type "ws"
      And   "Bob" receives invitation from "Alice"
      And   "Bob" approves invitation request with router "bob-router-connID"
      And   "Alice" approves did exchange request with router "alice-router-connID"
      And   "Alice,Bob" waits for post state event "completed"

    Then   "Alice,Bob" retrieves connection record and validates that connection state is "completed"
    Examples:
      | keyType    | keyAgreementType   | mediaTypeProfile          |
      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip1"            |
      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip2;env=rfc19"  |
#      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip2;env=rfc587" |
#      | "ED25519"  | "NISTP384ECDHKW"   | "didcomm/v2"              |

  Scenario Outline: Decentralized Identifier(DID) Exchange between two Edge Agents through Routers
    # DID Exchange between Alice and her Router
    Given options "<keyType>" "<keyAgreementType>" "<mediaTypeProfile>"
      And "Alice-Router" agent is running on "localhost" port "random" with "http" as the transport provider
      And "Alice-Router" creates a route exchange client
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
      And   "Alice-Router,Alice" waits for post state event "completed"

    Then   "Alice-Router,Alice" retrieves connection record and validates that connection state is "completed"
      And   "Alice" saves connectionID to variable "alice-router-connID"

     # DID Exchange between Bob and his Router
    Given "Bob" agent is running on "localhost" port "random" with "http" as the transport provider
      And   "Bob" creates did exchange client

    Given "Bob-Router" agent is running on "localhost" port "random" with "http" as the transport provider
      And "Bob-Router" creates a route exchange client
      And   "Bob-Router" creates did exchange client
      And   "Bob-Router" registers to receive notification for post state event "completed"
      And   "Bob" registers to receive notification for post state event "completed"

    When   "Bob-Router" creates invitation
      And   "Bob-Router" validates that invitation service endpoint of type "http"
      And   "Bob" receives invitation from "Bob-Router"
      And   "Bob" approves invitation request
      And   "Bob-Router" approves did exchange request
      And   "Bob-Router,Bob" waits for post state event "completed"

    Then   "Bob-Router,Bob" retrieves connection record and validates that connection state is "completed"
      And   "Bob" saves connectionID to variable "bob-router-connID"

       # Alice registers her Router
      And   "Alice" creates a route exchange client
      And   "Alice" sets "alice-router-connID" as the router and "Alice-Router" approves
      And   "Alice" verifies that the router connection id is set to "alice-router-connID"

       # Bob registers his Router
      And   "Bob" creates a route exchange client
      And   "Bob" sets "bob-router-connID" as the router and "Bob-Router" approves
      And   "Bob" verifies that the router connection id is set to "bob-router-connID"

     # DIDExchange between Alice and Bob through routers
    When   "Alice" creates invitation with router "alice-router-connID"
      And   "Alice" validates that invitation service endpoint of type "http"
      And   "Bob" receives invitation from "Alice"
      And   "Bob" approves invitation request with router "bob-router-connID"
      And   "Alice" approves did exchange request with router "alice-router-connID"
      And   "Alice,Bob" waits for post state event "completed"

    Then   "Alice,Bob" retrieves connection record and validates that connection state is "completed"
    Examples:
      | keyType    | keyAgreementType   | mediaTypeProfile          |
      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip1"            |
      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip2;env=rfc19"  |
#      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip2;env=rfc587" |
#      | "ED25519"  | "NISTP384ECDHKW"   | "didcomm/v2"              |

  # https://wiki.hyperledger.org/display/ARIES/DIDComm+MediatorRouter
  Scenario Outline: Decentralized Identifier(DID) Exchange between two Edge Agents(without Inbound) through Routers(HTTP/WS)
    # DID Exchange between Alice and her Router
    Given options "<keyType>" "<keyAgreementType>" "<mediaTypeProfile>"
      And "Alice-Router" agent is running on "localhost,localhost" port "random,random" with "http,websocket" as the transport provider
      And "Alice-Router" creates a route exchange client
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
      And   "Alice-Router,Alice" waits for post state event "completed"

    Then   "Alice-Router,Alice" retrieves connection record and validates that connection state is "completed"
      And   "Alice" saves connectionID to variable "alice-router-connID"
     # DID Exchange between Alice and her second router
    Given "Alice-second-Router" agent is running on "localhost,localhost" port "random,random" with "http,websocket" as the transport provider
    And "Alice-second-Router" creates a route exchange client
    And   "Alice-second-Router" creates did exchange client
    And   "Alice-second-Router" registers to receive notification for post state event "completed"

    When   "Alice-second-Router" creates invitation
    And   "Alice-second-Router" validates that invitation service endpoint of type "ws"
    And   "Alice" receives invitation from "Alice-second-Router"
    And   "Alice" approves invitation request
    And   "Alice-second-Router" approves did exchange request
    And   "Alice-second-Router,Alice" waits for post state event "completed"

    Then   "Alice-second-Router,Alice" retrieves connection record and validates that connection state is "completed"
    And   "Alice" saves connectionID to variable "alice-second-router-connID"

     # DID Exchange between Bob and his Router
    Given "Bob" edge agent is running with "http,websocket" as the outbound transport provider and "all" as the transport return route option
      And   "Bob" creates did exchange client

    Given "Bob-Router" agent is running on "localhost,localhost" port "random,random" with "http,websocket" as the transport provider
      And "Bob-Router" creates a route exchange client
      And   "Bob-Router" creates did exchange client
      And   "Bob-Router" registers to receive notification for post state event "completed"
      And   "Bob" registers to receive notification for post state event "completed"

    When   "Bob-Router" creates invitation
      And   "Bob-Router" validates that invitation service endpoint of type "ws"
      And   "Bob" receives invitation from "Bob-Router"
      And   "Bob" approves invitation request
      And   "Bob-Router" approves did exchange request
      And   "Bob-Router,Bob" waits for post state event "completed"

    Then   "Bob-Router,Bob" retrieves connection record and validates that connection state is "completed"
      And   "Bob" saves connectionID to variable "bob-router-connID"
     # DID Exchange between Bob and his Router
    Given "Bob-second-Router" agent is running on "localhost,localhost" port "random,random" with "http,websocket" as the transport provider
      And "Bob-second-Router" creates a route exchange client
      And   "Bob-second-Router" creates did exchange client
      And   "Bob-second-Router" registers to receive notification for post state event "completed"

    When   "Bob-second-Router" creates invitation
      And   "Bob-second-Router" validates that invitation service endpoint of type "ws"
      And   "Bob" receives invitation from "Bob-second-Router"
      And   "Bob" approves invitation request
      And   "Bob-second-Router" approves did exchange request
      And   "Bob-second-Router,Bob" waits for post state event "completed"

    Then   "Bob-second-Router,Bob" retrieves connection record and validates that connection state is "completed"
      And   "Bob" saves connectionID to variable "bob-second-router-connID"

       # Alice registers her Router
      And   "Alice" creates a route exchange client
      And   "Alice" sets "alice-router-connID" as the router and "Alice-Router" approves
      And   "Alice" verifies that the router connection id is set to "alice-router-connID"

       # Alice registers her second router
      And   "Alice" sets "alice-second-router-connID" as the router and "Alice-second-Router" approves
      And   "Alice" verifies that the router connection id is set to "alice-second-router-connID"

       # Bob registers his Router
      And   "Bob" creates a route exchange client
      And   "Bob" sets "bob-router-connID" as the router and "Bob-Router" approves
      And   "Bob" verifies that the router connection id is set to "bob-router-connID"
       # Bob registers his second router
      And   "Bob" sets "bob-second-router-connID" as the router and "Bob-second-Router" approves
      And   "Bob" verifies that the router connection id is set to "bob-second-router-connID"

     # DIDExchange between Alice and Bob through routers
    When   "Alice" creates invitation with router "alice-router-connID"
      And   "Alice" validates that invitation service endpoint of type "http"
      And   "Bob" receives invitation from "Alice"
      And   "Bob" approves invitation request with router "bob-router-connID"
      And   "Alice" approves did exchange request with router "alice-router-connID"
      And   "Alice,Bob" waits for post state event "completed"

    Then   "Alice,Bob" retrieves connection record and validates that connection state is "completed"
     # DIDExchange between Alice and Bob through routers (second connection)
    When   "Alice" creates invitation with router "alice-second-router-connID"
    And   "Alice" validates that invitation service endpoint of type "http"
    And   "Bob" receives invitation from "Alice"
    And   "Bob" approves invitation request with router "bob-second-router-connID"
    And   "Alice" approves did exchange request with router "alice-second-router-connID"
    And   "Alice,Bob" waits for post state event "completed"

    Then   "Alice,Bob" retrieves connection record and validates that connection state is "completed"
    Examples:
      | keyType    | keyAgreementType   | mediaTypeProfile          |
      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip1"            |
      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip2;env=rfc19"  |
#      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip2;env=rfc587" |
#      | "ED25519"  | "NISTP384ECDHKW"   | "didcomm/v2"              |
