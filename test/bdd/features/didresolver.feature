
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@didresolve
Feature: resolve did doc against sidetree using aries http binding did resolver
  @resolve_valid_did_doc
  Scenario: resolve did doc sidetree node
    Given "Mike" agent is running on "localhost" port "random" with http-binding did resolver url "${SIDETREE_URL}" which accepts did method "sidetree"
    When client sends request to sidetree "${SIDETREE_URL}" for create DID document "${DID_DOC_PATH}"
    Then "Mike" agent sucessfully resolves DID document
