#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@verifiable_jwt
Feature: Issue and verify Verifiable Credential and Verifiable Presentation in JWS format

  Scenario Outline: Issue VC - verify VC - create VP - verify VP
    Given crypto algorithm "<crypto>"
    And "Berkley" issues VC at "2022-04-12" regarding "Master Degree" to "Alice"
    Then "Alice" receives the VC and verifies it
    Then "Alice" embeds the VC into VP
    Then "Alice" verifies VP
    Examples:
      | crypto            |
      | "Ed25519"         |
      | "ECDSA Secp256r1" |
      | "ECDSA Secp384r1" |