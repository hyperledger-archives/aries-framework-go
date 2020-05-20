#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@verifiable
Feature: Issue Verifiable Credential
  @issue_vc_ldp_ed25519signature2018
  Scenario: Issue University Degree Credential with Ed25519Signature2018 Linked Data proof
    When "Stanford University" issues credential at "2018-03-15" regarding "Bachelor Degree" to "Alice" with "Ed25519Signature2018 Linked Data" proof
    Then "Alice" receives the credential and verifies it

  @issue_vc_ldp_jsonwebsignature2020_ec_p256
  Scenario: Issue University Degree Credential with JsonWebSignature2020 (EC P256) Linked Data proof
    When "Stanford University" issues credential at "2018-03-15" regarding "Bachelor Degree" to "Alice" with "JsonWebSignature2020 (EC P256) Linked Data" proof
    Then "Alice" receives the credential and verifies it

  @issue_vc_ldp_jsonwebsignature2020_ed25519
  Scenario: Issue University Degree Credential with JsonWebSignature2020 (Ed25519) Linked Data proof
    When "Stanford University" issues credential at "2018-03-15" regarding "Bachelor Degree" to "Alice" with "JsonWebSignature2020 (Ed25519) Linked Data" proof
    Then "Alice" receives the credential and verifies it

  @issue_vc_ldp_jsonwebsignature2020_ec_secp256k1
  Scenario: Issue University Degree Credential with JsonWebSignature2020 (secp256k1) Linked Data proof
    When "Stanford University" issues credential at "2018-03-15" regarding "Bachelor Degree" to "Alice" with "JsonWebSignature2020 (secp256k1) Linked Data" proof
    Then "Alice" receives the credential and verifies it

  @issue_vc_ldp_ecdsasecp256k1signature2019
  Scenario: Issue University Degree Credential with EcdsaSecp256k1Signature2019 Linked Data proof
    When "Stanford University" issues credential at "2018-03-15" regarding "Bachelor Degree" to "Alice" with "EcdsaSecp256k1Signature2019 Linked Data" proof
    Then "Alice" receives the credential and verifies it

  @issue_vc_jws
  Scenario: Issue University Degree Credential with JWS proof
    When "Berkley" issues credential at "2019-03-15" regarding "Master Degree" to "Bob" with "Ed25519 JWS" proof
    Then "Bob" receives the credential and verifies it
