#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@controller
@aries_router_controller
Feature: DIDComm V1 Transport between two Agents through DIDComm Routers [REST Binding]

  # https://wiki.hyperledger.org/display/ARIES/DIDComm+MediatorRouter
  Scenario: Decentralized Identifier(DID) Exchange between two Edge Agents(without Inbound) through Routers
    # DID Exchange between Carl and his Router
    Given "Carl" agent is running with controller "https://localhost:10081" and "all" as the transport return route option
    And   "Carl-Router" agent is running on "https://localhost:10091,wss://localhost:10092" with controller "https://localhost:10093"

    When   "Carl-Router" creates invitation through controller with label "carl-router-agent"
    And   "Carl" receives invitation from "Carl-Router" through controller

    Then   "Carl" approves exchange invitation through controller
    And   "Carl-Router" approves exchange request through controller

    Then   "Carl-Router,Carl" waits for post state event "completed" to web notifier
    And   "Carl-Router,Carl" retrieves connection record through controller and validates that connection state is "completed"
    And   "Carl" saves the connectionID to variable "carl-router-connID"
    # DID Exchange between Carl and his Router (second connection)
    When   "Carl-Router" creates invitation through controller with label "carl-second-router-agent"
    And   "Carl" receives invitation from "Carl-Router" through controller

    Then   "Carl" approves exchange invitation through controller
    And   "Carl-Router" approves exchange request through controller

    Then   "Carl-Router,Carl" waits for post state event "completed" to web notifier
    And   "Carl-Router,Carl" retrieves connection record through controller and validates that connection state is "completed"
    And   "Carl" saves the connectionID to variable "carl-second-router-connID"

     # DID Exchange between Dave and his Router
    Given "Dave" agent is running with controller "https://localhost:10041" and "all" as the transport return route option
    And   "Dave-Router" agent is running on "https://localhost:10051,wss://localhost:10052" with controller "https://localhost:10053"

    When   "Dave-Router" creates invitation through controller with label "Dave-router-agent"
    And   "Dave" receives invitation from "Dave-Router" through controller

    Then   "Dave" approves exchange invitation through controller
    And   "Dave-Router" approves exchange request through controller

    Then   "Dave-Router,Dave" waits for post state event "completed" to web notifier
    And   "Dave-Router,Dave" retrieves connection record through controller and validates that connection state is "completed"
    And   "Dave" saves the connectionID to variable "dave-router-connID"

    # DID Exchange between Dave and his Router (second connection)
    When   "Dave-Router" creates invitation through controller with label "Dave-second-router-agent"
    And   "Dave" receives invitation from "Dave-Router" through controller

    Then   "Dave" approves exchange invitation through controller
    And   "Dave-Router" approves exchange request through controller

    Then   "Dave-Router,Dave" waits for post state event "completed" to web notifier
    And   "Dave-Router,Dave" retrieves connection record through controller and validates that connection state is "completed"
    And   "Dave" saves the connectionID to variable "dave-second-router-connID"

    # Carl registers his routers
    Then   "Carl" unregisters the router with connection "carl-router-connID,carl-second-router-connID"
    And   "Carl" sets connection "carl-router-connID,carl-second-router-connID" as the router
    And   "Carl" verifies that the router connection is set to "carl-router-connID,carl-second-router-connID"

    # Dave registers his routers
    And   "Dave" unregisters the router with connection "dave-router-connID,dave-second-router-connID"
    And   "Dave" sets connection "dave-router-connID,dave-second-router-connID" as the router
    And   "Dave" verifies that the router connection is set to "dave-router-connID,dave-second-router-connID"

    # DIDExchange between Carl and Dave through routers
    When   "Carl" creates invitation through controller with label "carl-agent" and router "carl-router-connID"
    And   "Dave" receives invitation from "Carl" through controller

    Then   "Dave" approves exchange invitation with router "dave-router-connID" through controller
    And   "Carl" approves exchange request with router "carl-router-connID" through controller

    Then   "Carl,Dave" waits for post state event "completed" to web notifier
    And   "Carl,Dave" retrieves connection record through controller and validates that connection state is "completed"

    # DIDExchange between Carl and Dave through routers (second connection)
    When   "Carl" creates invitation through controller with label "carl-agent" and router "carl-second-router-connID"
    And   "Dave" receives invitation from "Carl" through controller

    Then   "Dave" approves exchange invitation with router "dave-second-router-connID" through controller
    And   "Carl" approves exchange request with router "carl-second-router-connID" through controller

    Then   "Carl,Dave" waits for post state event "completed" to web notifier
    And   "Carl,Dave" retrieves connection record through controller and validates that connection state is "completed"

    # Carl and Dave unregisters their routers in order to enable above flow with another protocol (legacy connection)
    Then   "Carl" unregisters the router with connection "carl-router-connID,carl-second-router-connID"
    And   "Dave" unregisters the router with connection "dave-router-connID,dave-second-router-connID"