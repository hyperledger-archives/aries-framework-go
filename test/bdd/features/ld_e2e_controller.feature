#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@controller
@ld_e2e_controller
Feature: JSON-LD operations using controller API

  Scenario: Controller API for remote JSON-LD context provider
    Given "Alice" agent is running on "localhost" port "8081" with controller "https://localhost:8082"

    When  "Alice" adds a new remote provider with endpoint "https://file-server.example.com:9099/vaccination-context.json" through controller
    Then  vaccination context from the provider is available to the agent instance
