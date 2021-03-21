#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@controller
@vdr_e2e_controller
Feature: VDR operation using controller API

  Scenario: create did using controller api
    Given "Alice" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
    When   "Alice" creates "peer" did through controller
