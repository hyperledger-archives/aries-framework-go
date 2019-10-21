
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@did_resolver_sidetree_node
Feature:
  @resolve_sidetree_node_valid_did_doc
  Scenario: resolve did doc sidetree node
    Given "Mike" agent is running on "localhost" port "random" with http-binding did resolver url "http://localhost:48326/.sidetree/document" which accepts did method "sidetree"
    When client sends request to sidetree "http://localhost:48326/.sidetree/document" for create DID document "fixtures/did_resolver_sidetree_node/config/didDocument.json"
    Then "Mike" agent sucessfully resolves DID document
