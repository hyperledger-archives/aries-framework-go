
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
    Given "Mike" agent is running on "localhost" port "random" with http-binding did resolver url "http://localhost:48326/.sidetree/document"
    When client sends request to sidetree "http://localhost:48326/.sidetree/document" for create DID document "fixtures/did_resolver_sidetree_node/config/didDocument.json"
    Then check success response contains "#didID"
    # we wait until observer poll sidetree txn from ledger
    Then we wait 1 seconds
    When "Mike" agent resolve DID document
