#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@didcomm_remote_crypto
Feature: DIDComm between DIDCommV2 agents using local KMS and web KMS

  Scenario: Wallet registers with Router using DIDComm V2, both agents using local KMS
    Given options ""ECDSAP256IEEEP1363"" ""NISTP256ECDHKW"" ""didcomm/v2""

    # wallet uses local kms
    Given "Wallet" edge agent is running with "websocket" outbound transport and transport return route "all" and "sidetree=${SIDETREE_URL}" flags
    # router uses local kms
    Given "Router" agent is running on "localhost" port "random" with "websocket" as the transport provider and "sidetree=${SIDETREE_URL}" flags

      And "Router" creates public DID for did method "sidetree"
      And "Router" waits for public did to become available in sidetree for up to 10 seconds

    # wallet needs did exchange client for the validate connection step
      And "Wallet" creates did exchange client

     When "Router" creates an out-of-band-v2 invitation
      And "Router" sends the request to "Wallet", which accepts it

     Then "Wallet" validates that connection to "Router" has state "completed"
      And "Wallet" saves connectionID to variable "Router-connID"

      And "Router" creates a route exchange client
      And "Wallet" creates a route exchange client

      And "Wallet" sets "Router-connID" as the router and "Router" approves
      And "Wallet" verifies that the router connection id is set to "Router-connID"

  Scenario: Wallet registers with Router using DIDComm V2, Wallet using web KMS, Router using local KMS
    Given options ""ECDSAP256IEEEP1363"" ""NISTP256ECDHKW"" ""didcomm/v2""

    # wallet uses web kms
    Given "Wallet" edge agent is running with "websocket" outbound transport and transport return route "all" and "sidetree=${SIDETREE_URL},kmsURL=https://localhost:8076" flags
    # router uses local kms
    Given "Router" agent is running on "localhost" port "random" with "websocket" as the transport provider and "sidetree=${SIDETREE_URL}" flags

      And "Router" creates public DID for did method "sidetree"
      And "Router" waits for public did to become available in sidetree for up to 10 seconds

    # wallet needs did exchange client for the validate connection step
      And "Wallet" creates did exchange client

     When "Router" creates an out-of-band-v2 invitation
      And "Router" sends the request to "Wallet", which accepts it

     Then "Wallet" validates that connection to "Router" has state "completed"
      And "Wallet" saves connectionID to variable "Router-connID"

      And "Router" creates a route exchange client
      And "Wallet" creates a route exchange client

      And "Wallet" sets "Router-connID" as the router and "Router" approves
      And "Wallet" verifies that the router connection id is set to "Router-connID"

  Scenario: Wallet registers with Router using DIDComm V2, both agents using web KMS
    Given options ""ECDSAP256IEEEP1363"" ""NISTP256ECDHKW"" ""didcomm/v2""
    # wallet uses web kms
    Given "Wallet" edge agent is running with "websocket" outbound transport and transport return route "all" and "sidetree=${SIDETREE_URL},kmsURL=https://localhost:8076" flags
    # router uses local kms
    Given "Router" agent is running on "localhost" port "random" with "websocket" as the transport provider and "sidetree=${SIDETREE_URL},kmsURL=https://localhost:8076" flags

      And "Router" creates public DID for did method "sidetree"
      And "Router" waits for public did to become available in sidetree for up to 10 seconds

    # wallet needs did exchange client for the validate connection step
      And "Wallet" creates did exchange client

     When "Router" creates an out-of-band-v2 invitation
      And "Router" sends the request to "Wallet", which accepts it

     Then "Wallet" validates that connection to "Router" has state "completed"
      And "Wallet" saves connectionID to variable "Router-connID"

      And "Router" creates a route exchange client
      And "Wallet" creates a route exchange client

      And "Wallet" sets "Router-connID" as the router and "Router" approves
      And "Wallet" verifies that the router connection id is set to "Router-connID"
