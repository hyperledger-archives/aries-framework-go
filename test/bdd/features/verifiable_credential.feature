#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@verifiable
Feature: Issue Verifiable Credential
  @issue_vc_ldp
  Scenario: Issue University Degree Credential with JWS Linked Data proof
    When "Stanford University" issues credential at "2018-03-15" regarding "Bachelor Degree" to "Alice" with "JWS Ed25519Signature2018 Linked data" proof
    Then "Alice" receives the credential and verifies it

  @issue_vc_jws
  Scenario: Issue University Degree Credential with JWS proof
    When "Berkley" issues credential at "2019-03-15" regarding "Master Degree" to "Bob" with "JWS" proof
    Then "Bob" receives the credential and verifies it
