#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange

@wallet_debugging
Feature: DIDComm between DIDCommV2 agents using local KMS and web KMS

  @wallet_debug_both_local
  Scenario: Wallet registers with Router using DIDComm V2, both agents using local KMS
    # wallet uses local kms
    Given "Wallet" edge agent is running with "websocket" outbound transport and transport return route "all" and "sidetree=${SIDETREE_URL},DIDCommV2" flags
    # router uses local kms
    Given "Router" agent is running on "localhost" port "random" with "websocket" as the transport provider and "sidetree=${SIDETREE_URL},DIDCommV2" flags

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

  @wallet_debug_wallet_webkms
  Scenario: Wallet registers with Router using DIDComm V2, Wallet using web KMS, Router using local KMS
    # wallet uses web kms
    Given "Wallet" edge agent is running with "websocket" outbound transport and transport return route "all" and "sidetree=${SIDETREE_URL},DIDCommV2,kmsURL=https://localhost:8076" flags
    # router uses local kms
    Given "Router" agent is running on "localhost" port "random" with "websocket" as the transport provider and "sidetree=${SIDETREE_URL},DIDCommV2" flags

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

  @wallet_debug_both_webkms
  Scenario: Wallet registers with Router using DIDComm V2, both agents using web KMS
    # wallet uses web kms
    Given "Wallet" edge agent is running with "websocket" outbound transport and transport return route "all" and "sidetree=${SIDETREE_URL},DIDCommV2,kmsURL=https://localhost:8076" flags
    # router uses local kms
    Given "Router" agent is running on "localhost" port "random" with "websocket" as the transport provider and "sidetree=${SIDETREE_URL},DIDCommV2,kmsURL=https://localhost:8076" flags

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
