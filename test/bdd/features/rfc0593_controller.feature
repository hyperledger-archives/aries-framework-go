#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@rfc0593
@rfc0593-rest
Feature: RFC0593 (REST API): JSON-LD Credential Attachment format for requesting and issuing credentials
  Background:
    Given "Holder" agent is running on "localhost" port "8081" with controller "https://localhost:8082"
      And "Issuer" agent is running on "localhost" port "9081" with controller "https://localhost:9082"
      And "Holder" and "Issuer" are connected via the controller API

  Scenario Outline: The Holder begins with a proposal
    Given controller API options "<proofPurpose>" "<created>" "<domain>" "<challenge>" "<proofType>"
     When "Holder" sends an RFC0593 proposal to the "Issuer" via the controller API
      And "Holder" replies to the Issuer's offer with a request
     Then "Holder" is issued the verifiable credential in JSONLD format via the controller API
    Examples:
      | proofPurpose    | created                | domain                 | challenge              | proofType            |
      | assertionMethod | "2010-07-13T09:15:36Z" | "ZZE6OFIIXOj0vYXvcCVt" | "6xFm2jL8997KiknMer6c" | Ed25519Signature2018 |
      | assertionMethod | "2010-07-16T11:30:32Z" | "3YZwKBjww8Kli14cLWIi" | "S876RnVrRJaHLUTj5Tev" | BbsBlsSignature2020  |

  Scenario Outline: The Issuer begins with an offer
    Given controller API options "<proofPurpose>" "<created>" "<domain>" "<challenge>" "<proofType>"
     When "Issuer" sends an RFC0593 offer to the "Holder" via the controller API
      And "Holder" replies to the Issuer's offer with a request
     Then "Holder" is issued the verifiable credential in JSONLD format via the controller API
    Examples:
      | proofPurpose    | created                | domain                 | challenge              | proofType            |
      | assertionMethod | "2010-11-21T12:15:19Z" | "eaHD1U8KCjKjlDAe8GdR" | "nB2MGbf7SPGqy7QG5Kp1" | Ed25519Signature2018 |
      | assertionMethod | "2012-04-15T13:30:58Z" | "7vm4W6bpA2cKkUcKIans" | "oi93EVbQyV96IOyzPNzX" | BbsBlsSignature2020  |

  Scenario Outline: The Holder begins with a request
    Given controller API options "<proofPurpose>" "<created>" "<domain>" "<challenge>" "<proofType>"
     When "Holder" sends an RFC0593 request to the "Issuer" via the controller API
     Then "Holder" is issued the verifiable credential in JSONLD format via the controller API
    Examples:
      | proofPurpose    | created                | domain                 | challenge              | proofType            |
      | assertionMethod | "2014-02-08T15:15:27Z" | "xT5SnlAf8TqjVDZxznKR" | "2aylYvkhw8dFTsog0zTS" | Ed25519Signature2018 |
      | assertionMethod | "2015-06-04T11:20:02Z" | "PvzYG8N72zJ0r1kctK2h" | "gaTEaCWReMBSx3Cu8EjT" | BbsBlsSignature2020  |
