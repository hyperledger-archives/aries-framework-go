#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Reference : https://identity.foundation/waci-presentation-exchange/#issuance-2

@waci_issuance
@waci_issuance_didcomm_v1
Feature: WACI Issuance (Go API, DIDComm V1 + Issue Credential V2)

  Background:
    Given all agents are using Media Type Profiles "didcomm/aip1,didcomm/aip2;env=rfc19"
    Given "Issuer" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    And "Holder" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"

  Scenario: Issuer issues a credential to the holder using the WACI Issuance flow
    Given "Issuer" creates public DID for did method "sidetree"
    And "Holder" creates public DID for did method "sidetree"
    Then "Issuer" waits for public did to become available in sidetree for up to 10 seconds
    And "Holder" waits for public did to become available in sidetree for up to 10 seconds
    Then "Issuer" creates an out-of-band-v1 invitation with streamlined-vc goal_code
    And "Issuer" sends the out-of-band-v1 invitation to "Holder" and they accept it
    Then "Holder" sends proposal credential V2 to the "Issuer" (WACI, DIDComm V1)
    And "Issuer" accepts a proposal V2 and sends an offer to the Holder (WACI, DIDComm V1)
    Then "Holder" accepts the offer and sends a Credential Application to the Issuer (DIDComm V1)
    And "Issuer" accepts the Credential Application and sends a credential to the Holder (DIDComm V1)
    Then "Holder" accepts the credential (DIDComm V1)
    And Holder checks that the expected credential was received in a Credential Response attachment (DIDComm V1)
