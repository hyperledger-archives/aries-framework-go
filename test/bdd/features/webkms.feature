#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange

@webkms
Feature: Decentralized Identifier(DID) exchange between the agents using SDK

  Scenario: user creates a key with agent using webkms
    Given "Andrii" agent is running on "localhost" port "random" with "http" as the transport provider using webkms with key server at "https://localhost:8076" URL, using "did:key:dummy-sample:sudesh" controller

    When  "Andrii" create "ED25519" key
    Then  "Andrii" gets non-empty key id

  Scenario: user exports a public key with agent using webkms
    Given "Andrii" agent is running on "localhost" port "random" with "http" as the transport provider using webkms with key server at "https://localhost:8076" URL, using "did:key:dummy-sample:sudesh" controller

    And   "Andrii" create "ED25519" key
    When  "Andrii" export public key
    Then  "Andrii" gets non-empty public key bytes

  Scenario: user creates and exports a key with agent using webkms
    Given "Andrii" agent is running on "localhost" port "random" with "http" as the transport provider using webkms with key server at "https://localhost:8076" URL, using "did:key:dummy-sample:sudesh" controller

    When  "Andrii" create and export "ED25519" key
    Then  "Andrii" gets non-empty key id
    And   "Andrii" gets non-empty public key bytes

  Scenario: user imports a private key with agent using webkms
    Given "Andrii" agent is running on "localhost" port "random" with "http" as the transport provider using webkms with key server at "https://localhost:8076" URL, using "did:key:dummy-sample:sudesh" controller

    When  "Andrii" import a private key with ID "keyID"
    Then  "Andrii" gets non-empty key id

  Scenario: user signs a message and verifies a signature with agent using webkms
    Given "Andrii" agent is running on "localhost" port "random" with "http" as the transport provider using webkms with key server at "https://localhost:8076" URL, using "did:key:dummy-sample:sudesh" controller
    And   "Andrii" create "ED25519" key

    When  "Andrii" sign "test message"
    Then  "Andrii" gets non-empty signature
    And   "Andrii" verifies signature for "test message"

  Scenario: user signs a encrypts/decrypts a message with agent using webkms
    Given "Andrii" agent is running on "localhost" port "random" with "http" as the transport provider using webkms with key server at "https://localhost:8076" URL, using "did:key:dummy-sample:sudesh" controller
    And   "Andrii" create "AES256GCM" key

    When  "Andrii" encrypt "test message" with "test aad" aad
    Then  "Andrii" gets non-empty ciphertext
    And   "Andrii" gets non-empty nonce

    When  "Andrii" decrypt ciphertext with "test aad" aad
    Then  "Andrii" gets plaintext with value "test message"

  Scenario: user signs a computes/verifies MAC with agent using webkms
    Given "Andrii" agent is running on "localhost" port "random" with "http" as the transport provider using webkms with key server at "https://localhost:8076" URL, using "did:key:dummy-sample:sudesh" controller
    And   "Andrii" create "HMACSHA256Tag256" key

    When  "Andrii" compute MAC for "test message"
    Then  "Andrii" gets non-empty MAC
    And   "Andrii" verifies MAC for "test message"

  Scenario: User A wraps A256GCM key for User B, User B successfully unwraps it
    Given "Andrii" agent is running on "localhost" port "random" with "http" as the transport provider using webkms with key server at "https://localhost:8076" URL, using "did:key:dummy-sample:sudesh" controller
    And   "Andrii" create "NISTP256ECDHKW" key

    Given "Baha" agent is running on "localhost" port "random" with "http" as the transport provider using webkms with key server at "https://localhost:8076" URL, using "did:key:dummy-sample:sudesh" controller
    And   "Baha" create "NISTP256ECDHKW" key
    And   "Baha" export public key

    When  "Andrii" wrap CEK with "Baha" public key
    Then  "Andrii" gets non-empty wrapped key

    When  "Baha" unwrap wrapped key from "Andrii"
    Then  "Baha" gets the same CEK as "Andrii"

  Scenario: User A wraps A256GCM key with sender key for User B, User B successfully unwraps it(Anoncrypt)
    Given "Andrii" agent is running on "localhost" port "random" with "http" as the transport provider using webkms with key server at "https://localhost:8076" URL, using "did:key:dummy-sample:sudesh" controller
    And   "Andrii" create and export "X25519ECDHKW" key

    Given "Baha" agent is running on "localhost" port "random" with "http" as the transport provider using webkms with key server at "https://localhost:8076" URL, using "did:key:dummy-sample:sudesh" controller
    And   "Baha" create and export "X25519ECDHKW" key


    When  "Andrii" wrap CEK with "Baha" public key and with sender key
    Then  "Andrii" gets non-empty wrapped key

    When  "Baha" unwrap wrapped key from "Andrii" with sender key
    Then  "Baha" gets the same CEK as "Andrii"

  Scenario: User A anonymously encrypts ("easy") a payload for User B, User B decrypts ("easy open") it
    Given "Andrii" agent is running on "localhost" port "random" with "http" as the transport provider using webkms with key server at "https://localhost:8076" URL, using "did:key:dummy-sample:sudesh" controller
    And   "Andrii" create and export "ED25519" key

    Given "Baha" agent is running on "localhost" port "random" with "http" as the transport provider using webkms with key server at "https://localhost:8076" URL, using "did:key:dummy-sample:sudesh" controller
    And   "Baha" create and export "ED25519" key

    When  "Andrii" easy "test payload" for "Baha"
    Then  "Andrii" gets non-empty ciphertext

    When  "Baha" easyOpen ciphertext from "Andrii"
    Then  "Baha" gets plaintext with value "test payload"

  Scenario: User B decrypts ("seal open") a payload that was encrypted ("seal") by User A
    Given "Andrii" agent is running on "localhost" port "random" with "http" as the transport provider using webkms with key server at "https://localhost:8076" URL, using "did:key:dummy-sample:sudesh" controller
    And   "Andrii" create and export "ED25519" key

    Given "Baha" agent is running on "localhost" port "random" with "http" as the transport provider using webkms with key server at "https://localhost:8076" URL, using "did:key:dummy-sample:sudesh" controller
    And   "Baha" create "ED25519" key

    When  "Baha" has sealed "test payload 2" for "Andrii"
    Then  "Baha" gets non-empty ciphertext

    When  "Andrii" sealOpen ciphertext from "Baha"
    Then  "Andrii" gets plaintext with value "test payload 2"
