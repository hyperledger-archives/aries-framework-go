#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@controller
@aries_router_controller
Feature: DIDComm Transport between two Agents through DIDComm Routers [REST Binding]

  # https://wiki.hyperledger.org/display/ARIES/DIDComm+MediatorRouter
  Scenario Outline: Decentralized Identifier(DID) Exchange between two Edge Agents(without Inbound) through Routers
    # DID Exchange between Carl (or Carl with DIDcomm V2) and his Router
    Given options "<keyType>" "<keyAgreementType>" "<mediaTypeProfile>" "<agent>" "<agentRouter>" "<transports>" "<agentControllerURL>" "<routerControllerURL>" "<routerConnID>" "<secondRouterConnID>" "<agent2>" "<agent2Router>" "<transports2>" "<agent2ControllerURL>" "<router2ControllerURL>" "<router2ConnID>" "<secondRouter2ConnID>"
    And   "<agent>" agent is running with controller "<agentControllerURL>" and "all" as the transport return route option
    And   "<agentRouter>" agent is running on "<transports>" with controller "<routerControllerURL>"

    When   "<agentRouter>" creates invitation through controller with label "carl-router-agent"
    And   "<agent>" receives invitation from "<agentRouter>" through controller

    Then   "<agent>" approves exchange invitation through controller
    And   "<agentRouter>" approves exchange request through controller

    Then   "<agentRouter>" and "<agent>" wait for post state event "completed" to web notifier
    And   "<agentRouter>" and "<agent>" retrieve connection record through controller and validate that connection state is "completed"
    And   "<agent>" saves the connectionID to variable "<routerConnID>"

    # DID Exchange between Carl and his Router (second connection)
    When   "<agentRouter>" creates invitation through controller with label "carl-second-router-agent"
    And   "<agent>" receives invitation from "<agentRouter>" through controller

    Then   "<agent>" approves exchange invitation through controller
    And   "<agentRouter>" approves exchange request through controller

    Then   "<agentRouter>" and "<agent>" wait for post state event "completed" to web notifier
    And   "<agentRouter>" and "<agent>" retrieve connection record through controller and validate that connection state is "completed"
    And   "<agent>" saves the connectionID to variable "<secondRouterConnID>"

     # DID Exchange between Dave and his Router
    Given "<agent2>" agent is running with controller "<agent2ControllerURL>" and "all" as the transport return route option
    And   "<agent2Router>" agent is running on "<transports2>" with controller "<router2ControllerURL>"

    When   "<agent2Router>" creates invitation through controller with label "Dave-router-agent"
    And   "<agent2>" receives invitation from "<agent2Router>" through controller

    Then   "<agent2>" approves exchange invitation through controller
    And   "<agent2Router>" approves exchange request through controller

    Then   "<agent2Router>" and "<agent2>" wait for post state event "completed" to web notifier
    And   "<agent2Router>" and "<agent2>" retrieve connection record through controller and validate that connection state is "completed"
    And   "<agent2>" saves the connectionID to variable "<router2ConnID>"

    # DID Exchange between Dave and his Router (second connection)
    When   "<agent2Router>" creates invitation through controller with label "Dave-second-router-agent"
    And   "<agent2>" receives invitation from "<agent2Router>" through controller

    Then   "<agent2>" approves exchange invitation through controller
    And   "<agent2Router>" approves exchange request through controller

    Then   "<agent2Router>" and "<agent2>" wait for post state event "completed" to web notifier
    And   "<agent2Router>" and "<agent2>" retrieve connection record through controller and validate that connection state is "completed"
    And   "<agent2>" saves the connectionID to variable "<secondRouter2ConnID>"

    # Carl registers his routers
    Then   "<agent>" unregisters the router with connection "<routerConnID>" and "<secondRouterConnID>"
    And   "<agent>" sets connection "<routerConnID>" and "<secondRouterConnID>" as the router
    And   "<agent>" verifies that the router connection is set to "<routerConnID>" and "<secondRouterConnID>"

    # Dave registers his routers
    And   "<agent2>" unregisters the router with connection "<router2ConnID>" and "<secondRouter2ConnID>"
    And   "<agent2>" sets connection "<router2ConnID>" and "<secondRouter2ConnID>" as the router
    And   "<agent2>" verifies that the router connection is set to "<router2ConnID>" and "<secondRouter2ConnID>"

    # DIDExchange between Carl and Dave through routers
    When   "<agent>" creates invitation through controller with label "carl-agent" and router "<routerConnID>"
    And   "<agent2>" receives invitation from "<agent>" through controller

    Then   "<agent2>" approves exchange invitation with router "<router2ConnID>" through controller
    And   "<agent>" approves exchange request with router "<routerConnID>" through controller

    Then   "<agent>" and "<agent2>" wait for post state event "completed" to web notifier
    And   "<agent>" and "<agent2>" retrieve connection record through controller and validate that connection state is "completed"

    # DIDExchange between Carl and Dave through routers (second connection)
    When   "<agent>" creates invitation through controller with label "carl-agent" and router "<secondRouterConnID>"
    And   "<agent2>" receives invitation from "<agent>" through controller

    Then   "<agent2>" approves exchange invitation with router "<secondRouter2ConnID>" through controller
    And   "<agent>" approves exchange request with router "<secondRouterConnID>" through controller

    Then   "<agent>" and "<agent2>" wait for post state event "completed" to web notifier
    And   "<agent>" and "<agent2>" retrieve connection record through controller and validate that connection state is "completed"
    Examples:
      | keyType    | keyAgreementType   | mediaTypeProfile          | agent     | agentRouter      | transports                                      | agentControllerURL        | routerControllerURL       | routerConnID             | secondRouterConnID              | agent2    | agent2Router     | transports2                                     | agent2ControllerURL       | router2ControllerURL      | router2ConnID            | secondRouter2ConnID             |
      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip1"            | "Carl"    | "Carl-Router"    | "https://localhost:10091,wss://localhost:10092" | "https://localhost:10081" | "https://localhost:10093" | "carl-router-connID"     | "carl-second-router-connID"     | "Dave"    | "Dave-Router"    | "https://localhost:10051,wss://localhost:10052" | "https://localhost:10041" | "https://localhost:10053" | "dave-router-connID"     | "dave-second-router-connID"     |
#      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip2;env=rfc19"  | "Carl1"   | "Carl-Router1"   | "https://localhost:10095,wss://localhost:10096" | "https://localhost:10083" | "https://localhost:10097" | "carl-router-connID2"    | "carl-second-router-connID2"    | "Dave1"   | "Dave-Router1"   | "https://localhost:10055,wss://localhost:10056" | "https://localhost:10043" | "https://localhost:10057" | "dave-router-connID2"    | "dave-second-router-connID2"    |
#      | "ED25519"  | "X25519ECDHKW"     | "didcomm/aip2;env=rfc587" | "CarlV2"  | "Carl-RouterV2"  | "https://localhost:10099,wss://localhost:10100" | "https://localhost:10085" | "https://localhost:10101" | "carl-router-v2-connID"  | "carl-second-router-v2-connID"  | "DaveV2"  | "Dave-RouterV2"  | "https://localhost:10059,wss://localhost:10060" | "https://localhost:10045" | "https://localhost:10061" | "dave-router-v2-connID"  | "dave-second-router-v2-connID"  |
#      | "ED25519"  | "NISTP384ECDHKW"   | "didcomm/v2"              | "Carl1V2" | "Carl-Router1V2" | "https://localhost:10103,wss://localhost:10104" | "https://localhost:10087" | "https://localhost:10105" | "carl-router-v2-connID2" | "carl-second-router-v2-connID2" | "Dave1V2" | "Dave-Router1V2" | "https://localhost:10063,wss://localhost:10064" | "https://localhost:10047" | "https://localhost:10065" | "dave-router-v2-connID2" | "dave-second-router-v2-connID2" |
