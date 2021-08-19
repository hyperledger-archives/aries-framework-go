#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@ld_e2e_sdk
Feature: JSON-LD operations using SDK client

  Scenario: Using SDK client for operations with remote JSON-LD context provider
    Given "Bob" agent is running on "localhost" port "random" with "http" as the transport provider

    When  "Bob" adds a new remote provider with endpoint "https://localhost:9099/citizenship-context.json" using client
    Then  "https://w3id.org/citizenship/v1" context from the provider is in agent's JSON-LD context store
