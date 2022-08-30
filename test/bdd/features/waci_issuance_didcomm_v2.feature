#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://identity.foundation/waci-presentation-exchange/#issuance-2

@waci_issuance
@waci_issuance_didcomm_v2
Feature: WACI Issuance (Go API, DIDComm V2 + Issue Credential V3)

  Background:
    Given all agents are using Media Type Profiles "didcomm/aip1,didcomm/aip2;env=rfc19,didcomm/aip2;env=rfc587,didcomm/v2"
    Given "Issuer" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    And "Holder" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"

  Scenario: Issuer issues a credential to the holder using the WACI Issuance flow
    Given "Issuer" creates public DID for did method "sidetree"
    And "Holder" creates public DID for did method "sidetree"
    Then "Issuer" waits for public did to become available in sidetree for up to 10 seconds
    And "Holder" waits for public did to become available in sidetree for up to 10 seconds
    Then "Issuer" creates an out-of-band-v2 invitation with streamlined-vc goal_code
    And "Issuer" sends the request to "Holder" and they accept it
    Then "Holder" sends proposal credential V3 to the "Issuer" (WACI)
    And "Issuer" accepts a proposal V3 and sends an offer to the Holder (WACI)
    Then "Holder" accepts the offer and sends a Credential Application to the Issuer
    And "Issuer" accepts the Credential Application and sends a credential to the Holder
    Then "Holder" accepts the credential
    And Holder checks that the expected credential was received in a Credential Response attachment
