#
# Copyright Avast Software. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/main/features/0160-connection-protocol

@all
@controller
@legacyconnection_e2e_controller
Feature: Establishing DIDComm V1 using Connection RFC-0160 protocol between the agents using controller API

  Scenario: legacy connection e2e flow using controller api
    Given "Alice" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
      And   "Bob" agent is running on "localhost" port "9081" with controller "https://localhost:9082"

    When   "Alice" creates legacy invitation through controller with label "alice-agent"
      And   "Bob" receives legacy invitation from "Alice" through controller
      And   "Bob" approves connection invitation through controller
      And   "Alice" approves connection request through controller
      And   "Alice" waits for legacy post state event "completed" to web notifier
      And   "Bob" waits for legacy post state event "completed" to web notifier

    Then   "Alice" retrieves connection record through controller and validates that legacy connection state is "completed"
      And   "Bob" retrieves connection record through controller and validates that legacy connection state is "completed"
