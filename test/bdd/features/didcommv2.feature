#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@didcommv2
Feature: DIDComm v2 features
  @didcommv2_did_rotation
  Scenario: DIDComm v2 DID rotation on connection after didexchange
    Given "Bart" agent is running on "localhost" port "random" with "http" as the transport provider and "sidetree=${SIDETREE_URL},DIDCommV2" flags
     And "Lisa" agent is running on "localhost" port "random" with "http" as the transport provider and "sidetree=${SIDETREE_URL},DIDCommV2" flags
    Given "Bart" creates public DID for did method "sidetree"
     And "Lisa" creates public DID for did method "sidetree"
     And "Bart" waits for public did to become available in sidetree for up to 10 seconds
     And "Lisa" waits for public did to become available in sidetree for up to 10 seconds
    Given "Bart" requests credential V3 from "Lisa"
     And "Lisa" accepts request V3 and sends credential to the Holder
     And "Bart" accepts credential with name "abcd"
     Then "Bart" checks that credential is being stored under "abcd" name
    When "Bart" rotates their connection to "Lisa" to new DID
     And "Bart" waits for public did to become available in sidetree for up to 10 seconds
     And "Bart" sends a request presentation v3 to the "Lisa"
     And "Lisa" accepts a request and sends a presentation v3 to the "Bart"
     And "Bart" accepts a presentation with name "license"
    Then "Bart" checks that presentation is being stored under "license" name
