#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://identity.foundation/waci-presentation-exchange/#issuance-2

@waci_issuance
Feature: WACI Issuance (Go API)

  Background:
    Given all agents are using Media Type Profiles "didcomm/aip1,didcomm/aip2;env=rfc19,didcomm/aip2;env=rfc587,didcomm/v2"
    Given "Issuer" uses http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
      And "Issuer" uses configured encryption parameters
      And "Issuer" is started with a "http" DIDComm endpoint

    Given "Holder" uses http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
      And "Holder" uses configured encryption parameters
      And "Holder" is started with a "http" DIDComm endpoint

  Scenario: Issuer issues a credential to the holder using the WACI Issuance flow
    Given "Issuer" creates public DID for did method "sidetree"
    And "Holder" creates public DID for did method "sidetree"
    Then "Issuer" waits for public did to become available in sidetree for up to 10 seconds
    And "Holder" waits for public did to become available in sidetree for up to 10 seconds
    Then "Issuer" creates an out-of-band-v2 invitation with streamlined-vc goal-code
    And "Issuer" sends the request to "Holder" and they accept it
    Then "Holder" sends proposal credential V3 to the "Issuer" (WACI)
    And "Issuer" accepts a proposal V3 and sends an offer to the Holder (WACI)
    Then "Holder" accepts the offer and sends a Credential Application to the Issuer
    And "Issuer" accepts the Credential Application and sends a credential to the Holder
    Then "Holder" accepts the credential
    And Holder checks that the expected credential was received in a Credential Fulfillment attachment
