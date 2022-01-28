
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@didresolver
Feature: resolve did doc against sidetree using aries http binding did resolver
  @resolve_valid_did_doc
  Scenario: resolve did doc sidetree node
    Given "Mike" uses http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
      And "Mike" uses configured encryption parameters
      And "Mike" is started with a "http" DIDComm endpoint

    When "Mike" creates public DID for did method "sidetree"
    Then "Mike" agent successfully resolves DID document
