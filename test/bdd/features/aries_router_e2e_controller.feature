#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@aries_router_controller
Feature: DIDComm Transport between two Agents through DIDComm Routers [REST Binding]

  # https://wiki.hyperledger.org/display/ARIES/DIDComm+MediatorRouter
  Scenario: Decentralized Identifier(DID) Exchange between two Edge Agents(without Inbound) through Routers
    # DID Exchange between Carl and his Router
    Given "Carl" agent is running with controller "http://localhost:10081" and webhook "http://localhost:10082" and "all" as the transport return route option
    And   "Carl-Router" agent is running on "http://localhost:10091,ws://localhost:10092" with controller "http://localhost:10093" and webhook "http://localhost:10094"

    When   "Carl-Router" creates invitation through controller with label "carl-router-agent"
    And   "Carl" receives invitation from "Carl-Router" through controller

    Then   "Carl" approves exchange invitation through controller
    And   "Carl-Router" approves exchange request through controller

    Then   "Carl-Router" waits for post state event "completed" to webhook
    And   "Carl" waits for post state event "completed" to webhook

    Then   "Carl-Router" retrieves connection record through controller and validates that connection state is "completed"
    And   "Carl" retrieves connection record through controller and validates that connection state is "completed"
    And   "Carl" saves the connectionID to variable "carl-router-connID"

     # DID Exchange between Dave and his Router
    Given "Dave" agent is running with controller "http://localhost:10061" and webhook "http://localhost:10062" and "all" as the transport return route option
    And   "Dave-Router" agent is running on "http://localhost:10071,ws://localhost:10092" with controller "http://localhost:10073" and webhook "http://localhost:10074"

    When   "Dave-Router" creates invitation through controller with label "Dave-router-agent"
    And   "Dave" receives invitation from "Dave-Router" through controller

    Then   "Dave" approves exchange invitation through controller
    And   "Dave-Router" approves exchange request through controller

    Then   "Dave-Router" waits for post state event "completed" to webhook
    And   "Dave" waits for post state event "completed" to webhook

    Then   "Dave-Router" retrieves connection record through controller and validates that connection state is "completed"
    And   "Dave" retrieves connection record through controller and validates that connection state is "completed"
    And   "Dave" saves the connectionID to variable "dave-router-connID"

       # Carl registers her Router
    And   "Carl" unregisters the router
    And   "Carl" sets connection "carl-router-connID" as the router
    And   "Carl" verifies that the router connection is set to "carl-router-connID"

       # Dave registers his Router
    And   "Dave" unregisters the router
    And   "Dave" sets connection "dave-router-connID" as the router
    And   "Dave" verifies that the router connection is set to "dave-router-connID"

     # DIDExchange between Alice and Bob through routers
    When   "Carl" creates invitation through controller with label "carl-agent"
    And   "Dave" receives invitation from "Carl" through controller

    Then   "Dave" approves exchange invitation through controller
    And   "Carl" approves exchange request through controller

    Then   "Carl" waits for post state event "completed" to webhook
    And   "Dave" waits for post state event "completed" to webhook

    Then   "Carl" retrieves connection record through controller and validates that connection state is "completed"
    And   "Dave" retrieves connection record through controller and validates that connection state is "completed"
