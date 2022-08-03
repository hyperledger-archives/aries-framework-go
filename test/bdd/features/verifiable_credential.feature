#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

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

@interop_jwt_verifiable
  Scenario: Load and verify Interop JWT credentials
    When loading file "interop_credential_1_ed25519.jwt" signed using "Ed25519" and verify it
    And  loading file "interop_credential_2_ed25519.jwt" signed using "Ed25519" and verify it
    And  loading file "interop_credential_3_ed25519.jwt" signed using "Ed25519" and verify it
    And  loading file "interop_credential_4_secp256k1.jwt" signed using "secp256k1" and verify it
    And  loading file "interop_credential_5_secp256k1.jwt" signed using "secp256k1" and verify it
    And  loading file "interop_credential_6_secp256k1.jwt" signed using "secp256k1" and verify it
    And  loading file "interop_credential_7_secp256r1.jwt" signed using "secp256r1" and verify it
    And  loading file "interop_credential_8_secp256r1.jwt" signed using "secp256r1" and verify it
    And  loading file "interop_credential_9_secp256r1.jwt" signed using "secp256r1" and verify it
    And  loading file "interop_credential_10_secp384r1.jwt" signed using "secp384r1" and verify it
    And  loading file "interop_credential_11_secp384r1.jwt" signed using "secp384r1" and verify it
    And  loading file "interop_credential_12_secp384r1.jwt" signed using "secp384r1" and verify it
