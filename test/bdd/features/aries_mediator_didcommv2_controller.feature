#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@aries_router_didcommv2_controller
Feature: DIDComm V2 Transport between two Agents through DIDComm Routers [REST Binding]

  # https://wiki.hyperledger.org/display/ARIES/DIDComm+MediatorRouter
  Scenario: Decentralized Identifier(DID) Exchange between two Edge Agents(without Inbound) through Routers
    # DID Exchange between Carl and his Router
    Given "Carl" agent is running with controller "https://localhost:10081" and "all" as the transport return route option
    And   "Carl-Router" agent is running on "https://localhost:10091,wss://localhost:10092" with controller "https://localhost:10093"

    # dummy agent with same name, to wait for public DID
    And   "Carl-Router" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    And   "Carl-Router" creates "sidetree" did through controller
    And   "Carl-Router" waits for public did to become available in sidetree for up to 10 seconds

    When  "Carl-Router" creates an out-of-band-v2 invitation (controller)
    And   the OOBv2 invitation from "Carl-Router" is accepted by "Carl" (controller)

    #And   "Carl-Router,Carl" retrieves connection record through controller and validates that connection state is "completed"
    And   "Carl" retrieves connection record through controller and validates that connection state is "completed"
    And   "Carl" saves the connectionID to variable "carl-router-connID"

     # DID Exchange between Dave and his Router
    Given "Dave" agent is running with controller "https://localhost:10041" and "all" as the transport return route option
    And   "Dave-Router" agent is running on "https://localhost:10051,wss://localhost:10052" with controller "https://localhost:10053"

    # dummy agent with same name, to create public DID
    And   "Dave-Router" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    And   "Dave-Router" creates "sidetree" did through controller
    And   "Dave-Router" waits for public did to become available in sidetree for up to 10 seconds

    When  "Dave-Router" creates an out-of-band-v2 invitation (controller)
    And   the OOBv2 invitation from "Dave-Router" is accepted by "Dave" (controller)

    And   "Dave" retrieves connection record through controller and validates that connection state is "completed"
    And   "Dave" saves the connectionID to variable "dave-router-connID"

    # Carl registers his routers
    Then   "Carl" unregisters the router with connection "carl-router-connID"
    And   "Carl" sets connection "carl-router-connID" as the router
    And   "Carl" verifies that the router connection is set to "carl-router-connID"

    # Dave registers his routers
    And   "Dave" unregisters the router with connection "dave-router-connID"
    And   "Dave" sets connection "dave-router-connID" as the router
    And   "Dave" verifies that the router connection is set to "dave-router-connID"

    # DIDExchange between Carl and Dave through routers
    When   "Carl" creates invitation through controller with label "carl-agent" and router "carl-router-connID"
    And   "Dave" receives invitation from "Carl" through controller

    Then   "Dave" approves exchange invitation with router "dave-router-connID" through controller
    And   "Carl" approves exchange request with router "carl-router-connID" through controller

    Then   "Carl,Dave" waits for post state event "completed" to web notifier
    And   "Carl,Dave" retrieves connection record through controller and validates that connection state is "completed"
