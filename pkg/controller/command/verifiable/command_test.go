/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	jsonldsig "github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
	kmsapi "github.com/hyperledger/aries-framework-go/pkg/kms"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	kmsmock "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	verifiablestore "github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
)

const (
	sampleCredentialName   = "sampleVCName"
	sampleVCID             = "http://example.edu/credentials/1989"
	samplePresentationName = "sampleVpName"
)

const vc = `
{ 
   "@context":[ 
      "https://www.w3.org/2018/credentials/v1", 
	  "https://trustbloc.github.io/context/vc/examples-v1.jsonld"
   ],
   "id":"http://example.edu/credentials/1989",
   "type":"VerifiableCredential",
   "credentialSubject":{ 
      "id":"did:example:iuajk1f712ebc6f1c276e12ec21"
   },
   "issuer":{ 
      "id":"did:example:09s12ec712ebc6f1c671ebfeb1f",
      "name":"Example University"
   },
   "issuanceDate":"2020-01-01T10:54:01Z",
   "credentialStatus":{ 
      "id":"https://example.gov/status/65",
      "type":"CredentialStatusList2017"
   }
}
`

const bbsVc = `{
   "@context":[
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1",
      "https://w3id.org/security/bbs/v1"
   ],
   "credentialSubject":{
      "degree":{
         "degree":"MIT",
         "degreeSchool":"MIT school",
         "type":"BachelorDegree"
      },
      "id":"did:example:b34ca6cd37bbf23",
      "name":"Jayden Doe",
      "spouse":"did:example:c276e12ec21ebfeb1f712ebc6f1"
   },
   "description":"Government of Example Permanent Resident Card.",
   "expirationDate":"2022-03-04T11:53:29.728412319+02:00",
   "id":"https://issuer.oidp.uscis.gov/credentials/83627465",
   "identifier":"83627465",
   "issuanceDate":"2021-03-04T11:53:29.728412269+02:00",
   "issuer":"did:example:489398593",
   "name":"Permanent Resident Card",
   "type":[
      "VerifiableCredential",
      "UniversityDegreeCredential"
   ]
}`

const authVC = `{
	"@context": [
		"https://www.w3.org/2018/credentials/v1", 
		"https://trustbloc.github.io/context/vc/authorization-credential-v1.jsonld"
	],
	"credentialSubject": {
		"id": "did:peer:1zQmXJMfYLECQagWsw57tTDtudqp8eT2FTFd4Wiy1YUxQvMw",
		"issuerDIDDoc": {
			"doc": {
				"@context": ["https://www.w3.org/ns/did/v1"],
				"assertionMethod": ["#key-1"],
				"authentication": ["#key-1"],
				"created": "2021-09-16T01:44:39.7337939Z",
				"id": "did:peer:1zQmYEVm9usSN4UdR3bRH2GLzbbcdrzSMEXvgLweekn3yr66",
				"keyAgreement": ["#key-2"],
				"service": [{
					"id": "038ecea0-06bd-495c-a2bd-df32f9a68aec",
					"priority": 0,
					"recipientKeys": ["did:key:z6Mkg3kFC6kLTZ9pqwzJrTpztq3FV7RsVVyXPrpJ8ZyAtYZJ"],
					"routingKeys": [],
					"serviceEndpoint": "http://mock-issuer-adapter.com:10010",
					"type": "did-communication"
				}],
				"updated": "2021-09-16T01:44:39.7337939Z",
				"verificationMethod": [{
					"controller": "",
					"id": "#key-1",
					"publicKeyBase58": "2bVCbrVu81fMjT9cAtsA3jVFfYA25cjAhquNJJ19yKmv",
					"type": "Ed25519VerificationKey2018"
				}, {
					"controller": "",
					"id": "#key-2",
					"publicKeyBase58": "4gj2K8KWyCQAxQyefUubHDSdakSNuLWatkHfcNtWuXa1",
					"type": "X25519KeyAgreementKey2019"
				}]
			},
			"id": "did:peer:1zQmYEVm9usSN4UdR3bRH2GLzbbcdrzSMEXvgLweekn3yr66"
		},
		"requestingPartyDIDDoc": {
			"doc": {
				"@context": ["https://www.w3.org/ns/did/v1"],
				"assertionMethod": ["#oBCLqpUt8SaReCcRyTJVlBAEVQTTaOT7H1QfdFBKoDI"],
				"authentication": ["#oBCLqpUt8SaReCcRyTJVlBAEVQTTaOT7H1QfdFBKoDI"],
				"created": "2021-09-16T01:45:23.4119263Z",
				"id": "did:peer:1zQmeiHBZ2ymS7S43X43hGhJth5Fxc3uSaRcQ3ECwz7MFQvD",
				"service": [{
					"id": "57c0c1e7-8171-43e4-8b2a-60a695cd452c",
					"priority": 0,
					"recipientKeys": ["did:key:z6Mkmjb9tNbRnL3vpR5Pt6qEtYE8MeL8BvSBAd7iD2p2wYDh"],
					"routingKeys": [],
					"serviceEndpoint": "http://rp.adapter.rest.example.com:8071",
					"type": "did-communication"
				}],
				"updated": "2021-09-16T01:45:23.4119263Z",
				"verificationMethod": [{
					"controller": "",
					"id": "#oBCLqpUt8SaReCcRyTJVlBAEVQTTaOT7H1QfdFBKoDI",
					"publicKeyBase58": "8HL7J8LzSnZThvEhCXsQ3Sg8Y54Gn3BpUcCnNkr22KSK",
					"type": "Ed25519VerificationKey2018"
				}]
			},
			"id": "did:peer:1zQmeiHBZ2ymS7S43X43hGhJth5Fxc3uSaRcQ3ECwz7MFQvD"
		},
		"subjectDIDDoc": {
			"doc": {
				"@context": ["https://www.w3.org/ns/did/v1"],
				"assertionMethod": ["#key-1"],
				"authentication": ["#key-1"],
				"created": "2021-09-16T01:44:39.7286951Z",
				"id": "did:peer:1zQmXJMfYLECQagWsw57tTDtudqp8eT2FTFd4Wiy1YUxQvMw",
				"keyAgreement": ["#key-2"],
				"service": [{
					"id": "ec900fc4-29c2-43a4-91df-3098d617a981",
					"priority": 0,
					"recipientKeys": ["did:key:z6MkibZkEZAGr3HZfbWNiSBR8dvNnpZmSXm5A9weBMrTKjk3"],
					"routingKeys": [],
					"serviceEndpoint": "http://mock-wallet.com:9081",
					"type": "did-communication"
				}],
				"updated": "2021-09-16T01:44:39.7286951Z",
				"verificationMethod": [{
					"controller": "",
					"id": "#key-1",
					"publicKeyBase58": "59JheJuqWVo6Z6fg2sDaHYNNyFHv2eWiU92iM5tSQWxf",
					"type": "Ed25519VerificationKey2018"
				}, {
					"controller": "",
					"id": "#key-2",
					"publicKeyBase58": "9MFKK9MeTCCD1irEWcLv4hYwM9v5APovXNzzLoZdFQ3L",
					"type": "X25519KeyAgreementKey2019"
				}]
			},
			"id": "did:peer:1zQmXJMfYLECQagWsw57tTDtudqp8eT2FTFd4Wiy1YUxQvMw"
		}
	},
	"id": "http://example.gov/credentials/ff98f978-588f-4eb0-b17b-60c18e1dac2c",
	"issuanceDate": "2020-03-16T22:37:26.544Z",
	"issuer": "did:peer:1zQmXJMfYLECQagWsw57tTDtudqp8eT2FTFd4Wiy1YUxQvMw",
	"type": ["VerifiableCredential", "AuthorizationCredential"]
}`

//nolint:lll
const vcWithDIDNotAvailble = `{ 
   "@context":[ 
      "https://www.w3.org/2018/credentials/v1",
      "https://trustbloc.github.io/context/vc/examples-v1.jsonld"
   ],
   "id":"http://example.edu/credentials/1989",
   "type":"VerifiableCredential",
   "credentialSubject":{ 
      "id":"did:example:iuajk1f712ebc6f1c276e12ec21"
   },
   "issuer":{ 
      "id":"did:example:09s12ec712ebc6f1c671ebfeb1f",
      "name":"Example University"
   },
   "issuanceDate":"2020-01-01T10:54:01Z",
   "credentialStatus":{ 
      "id":"https://example.gov/status/65",
      "type":"CredentialStatusList2017"
   },
   "proof": {
        "created": "2020-04-17T04:17:48Z",
        "proofPurpose": "assertionMethod",
        "proofValue": "CAQJKqd0MELydkNdPh7TIwgKhcMt_ypQd8AUdTbFUU4VVQVpPhEZLjg1U-1lBJyluRejsNbHZCJDRptPkBuqAQ",
        "type": "Ed25519Signature2018",
        "verificationMethod": "did:trustbloc:testnet.trustbloc.local:EiABBmUZ7Jjp-mlxWJInqp3Ak2v82QQtCdIUS5KSTNGq9Q==#key-1"
    }
}`

const invalidVC = `
{
   "id":"http://example.edu/credentials/1989",
   "type":"VerifiableCredential",
   "credentialSubject":{ 
      "id":"did:example:iuajk1f712ebc6f1c276e12ec21"
   },
   "issuer":{ 
      "id":"did:example:09s12ec712ebc6f1c671ebfeb1f",
      "name":"Example University"
   },
   "issuanceDate":"2020-01-01T10:54:01Z",
   "credentialStatus":{ 
      "id":"https://example.gov/status/65",
      "type":"CredentialStatusList2017"
   }
}
`

//nolint:lll
const doc = `{
  "@context": ["https://w3id.org/did/v1","https://w3id.org/did/v2"],
  "id": "did:peer:123456789abcdefghi#inbox",
  "authentication": ["did:peer:123456789abcdefghi#keys-1"],
  "assertionMethod": ["did:peer:123456789abcdefghi#keys-1"],
  "verificationMethod": [
    {
      "id": "did:peer:123456789abcdefghi#keys-1",
      "type": "Secp256k1VerificationKey2018",
      "controller": "did:peer:123456789abcdefghi",
      "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    },
    {
      "id": "did:peer:123456789abcdefghw#key2",
      "type": "RsaVerificationKey2018",
      "controller": "did:peer:123456789abcdefghw",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAryQICCl6NZ5gDKrnSztO\n3Hy8PEUcuyvg/ikC+VcIo2SFFSf18a3IMYldIugqqqZCs4/4uVW3sbdLs/6PfgdX\n7O9D22ZiFWHPYA2k2N744MNiCD1UE+tJyllUhSblK48bn+v1oZHCM0nYQ2NqUkvS\nj+hwUU3RiWl7x3D2s9wSdNt7XUtW05a/FXehsPSiJfKvHJJnGOX0BgTvkLnkAOTd\nOrUZ/wK69Dzu4IvrN4vs9Nes8vbwPa/ddZEzGR0cQMt0JBkhk9kU/qwqUseP1QRJ\n5I1jR4g8aYPL/ke9K35PxZWuDp3U0UPAZ3PjFAh+5T+fc7gzCs9dPzSHloruU+gl\nFQIDAQAB\n-----END PUBLIC KEY-----"
    },
	{
        "type": "Ed25519VerificationKey2018",
        "publicKeyBase58": "GUXiqNHCdirb6NKpH6wYG4px3YfMjiCh6dQhU3zxQVQ7",
        "id": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ#signing-key",
        "controller": "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ"
    }

  ]
}`

const authDoc = `{
	"@context": ["https://www.w3.org/ns/did/v1"],
	"assertionMethod": ["#key-1"],
	"authentication": ["#key-1"],
	"created": "2021-09-16T01:44:39.7337939Z",
	"id": "did:peer:1zQmYEVm9usSN4UdR3bRH2GLzbbcdrzSMEXvgLweekn3yr66",
	"keyAgreement": ["#key-2"],
	"service": [{
		"id": "038ecea0-06bd-495c-a2bd-df32f9a68aec",
		"priority": 0,
		"recipientKeys": ["did:key:z6Mkg3kFC6kLTZ9pqwzJrTpztq3FV7RsVVyXPrpJ8ZyAtYZJ"],
		"routingKeys": [],
		"serviceEndpoint": "http://mock-issuer-adapter.com:10010",
		"type": "did-communication"
	}],
	"updated": "2021-09-16T01:44:39.7337939Z",
	"verificationMethod": [{
		"controller": "",
		"id": "#key-1",
		"publicKeyBase58": "2bVCbrVu81fMjT9cAtsA3jVFfYA25cjAhquNJJ19yKmv",
		"type": "Ed25519VerificationKey2018"
	}, {
		"controller": "",
		"id": "#key-2",
		"publicKeyBase58": "4gj2K8KWyCQAxQyefUubHDSdakSNuLWatkHfcNtWuXa1",
		"type": "X25519KeyAgreementKey2019"
	}]
}`

const invalidDoc = `{
  "@context": ["https://w3id.org/did/v1","https://w3id.org/did/v2"],
  "id": "did:peer:21tDAKCERh95uGgKbJNHYp",
  "verificationMethod": [
  ]
}`

//nolint:lll
const jwsDIDDoc = `{
    "@context":["https://w3id.org/did/v1"], 
	"id": "did:trustbloc:testnet.trustbloc.local:EiBug_0h2oNJj4Vhk7yrC36HvskhngqTJC46VKS-FDM5fA",
	"authentication" : [ "did:trustbloc:testnet.trustbloc.local:EiBug_0h2oNJj4Vhk7yrC36HvskhngqTJC46VKS-FDM5fA#key-7777" ],
	"assertionMethod" : [ "did:trustbloc:testnet.trustbloc.local:EiBug_0h2oNJj4Vhk7yrC36HvskhngqTJC46VKS-FDM5fA#key-7777" ],
    "verificationMethod": [{
            "controller": "did:trustbloc:testnet.trustbloc.local:EiBug_0h2oNJj4Vhk7yrC36HvskhngqTJC46VKS-FDM5fA",
            "id": "did:trustbloc:testnet.trustbloc.local:EiBug_0h2oNJj4Vhk7yrC36HvskhngqTJC46VKS-FDM5fA#key-7777",
            "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "tp-lwePd7QnwWaxCLZ76-fPj2mjA-3z_ivCfBmZoDNA"},
            "type": "JwsVerificationKey2020"
        }]
}
`

//nolint:lll
const didKeyDoc = `{
  "@context" : [ "https://w3id.org/did/v0.11" ],
  "id" : "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
  "authentication" : [ 
		"did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
		"did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#XiRjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd"],
  "assertionMethod" : [ "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd" ],
  "capabilityDelegation" : [ "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd" ],
  "capabilityInvocation" : [ "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd" ],
  "keyAgreement" : [ {
    "id" : "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6LShKMZ117txS1WuExddVM2rbJ2zy3AKFtZVY5WNi44aKzA",
    "type" : "X25519KeyAgreementKey2019",
    "controller" : "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
    "publicKeyBase58" : "6eBPUhK2ryHmoras6qq5Y15Z9pW3ceiQcZMptFQXrxDQ"
  } ],
  "verificationMethod" : [ {
    "id" : "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
    "type" : "Ed25519VerificationKey2018",
    "controller" : "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
    "publicKeyBase58" : "5yKdnU7ToTjAoRNDzfuzVTfWBH38qyhE1b9xh4v8JaWF"
  },
  {
    "id" : "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#XiRjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
    "type" : "Ed25519VerificationKey2018",
    "controller" : "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
    "publicKeyBase58" : "5yKdnU7ToTjAoRNDzfuzVTfWBH38qyhE1b9xh4v8JaWF"
  }]
}`

//nolint:lll
const tbDoc = `{
  "@context": [
    "https://w3id.org/did/v1"
  ],
  "authentication": [
    "#bG9jYWwtbG9jazovL2RlZmF1bHQvbWFzdGVyL2tleS96cThTc3JJZ0JVTHhveU9XU2tLZ2drQWJhcjJhVDVHTmlXbERuY244VlYwPQ"
  ],
  "id": "did:trustbloc:testnet.trustbloc.local:EiAzdTbGPXhvC0ESOcnlR7nCWkN1m1XUJ04uEG9ayhRbPg",
  "verificationMethod": [
    {
      "controller": "did:trustbloc:testnet.trustbloc.local:EiAzdTbGPXhvC0ESOcnlR7nCWkN1m1XUJ04uEG9ayhRbPg",
      "id": "did:trustbloc:testnet.trustbloc.local:EiAzdTbGPXhvC0ESOcnlR7nCWkN1m1XUJ04uEG9ayhRbPg#bG9jYWwtbG9jazovL2RlZmF1bHQvbWFzdGVyL2tleS96cThTc3JJZ0JVTHhveU9XU2tLZ2drQWJhcjJhVDVHTmlXbERuY244VlYwPQ",
      "publicKeyBase58": "7yJkjsEqXSjVyqETXobYzpesAY8zgQyomS54nN3KHZqg",
      "type": "Ed25519VerificationKey2018"
    }
  ]
}`

//nolint:lll
const tbDocNoAuth = `{
  "@context": [
    "https://w3id.org/did/v1"
  ],
  "id": "did:trustbloc:testnet.trustbloc.local:EiAzdTbGPXhvC0ESOcnlR7nCWkN1m1XUJ04uEG9ayhRbPg1",
  "verificationMethod": [
    {
      "controller": "did:trustbloc:testnet.trustbloc.local:EiAzdTbGPXhvC0ESOcnlR7nCWkN1m1XUJ04uEG9ayhRbPg1",
      "id": "did:trustbloc:testnet.trustbloc.local:EiAzdTbGPXhvC0ESOcnlR7nCWkN1m1XUJ04uEG9ayhRbPg1#bG9jYWwtbG9jazovL2RlZmF1bHQvbWFzdGVyL2tleS96cThTc3JJZ0JVTHhveU9XU2tLZ2drQWJhcjJhVDVHTmlXbERuY244VlYwPQ",
      "publicKeyBase58": "7yJkjsEqXSjVyqETXobYzpesAY8zgQyomS54nN3KHZqg",
      "type": "Ed25519VerificationKey2018"
    }
  ]
}`

//nolint:lll
const udVerifiablePresentation = `{
        "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
        "type": ["VerifiablePresentation"],
        "verifiableCredential": [{
            "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
            "credentialSchema": [],
            "credentialStatus": {
                "id": "http://issuer.vc.rest.example.com:8070/status/1",
                "type": "CredentialStatusList2017"
            },
            "credentialSubject": {
                "degree": {"degree": "MIT", "type": "BachelorDegree"},
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "name": "Jayden Doe",
                "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
            },
            "id": "https://example.com/credentials/9315d0fd-da93-436e-9e20-2121f2821df3",
            "issuanceDate": "2020-03-16T22:37:26.544Z",
            "issuer": {
                "id": "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg",
                "name": "alice_ca31684e-6cbb-40f9-b7e6-87e1ab5661ae"
            },
            "proof": {
                "created": "2020-04-08T21:19:02Z",
                "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..yGHHYmRp4mWd918SDSzmBDs8eq-SX7WPl8moGB8oJeSqEMmuEiI81D4s5-BPWGmKy3VlCsKJxYrTNqrEGJpNAQ",
                "proofPurpose": "assertionMethod",
                "type": "Ed25519Signature2018",
                "verificationMethod": "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg#xqc3gS1gz1vch7R3RvNebWMjLvBOY-n_14feCYRPsUo"
            },
            "type": ["VerifiableCredential", "UniversityDegreeCredential"]
        }],
        "proof": {
            "created": "2020-04-08T17:19:05-04:00",
            "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..0CH8GwphcMoQ0JHCm1O8n9ctM-s8hTfTuOa-WeQFSmPipaO41pECe7pQ4zDM6sp08W59pkrTz_U1PrwLlUyoBw",
            "proofPurpose": "assertionMethod",
            "type": "Ed25519Signature2018",
            "verificationMethod": "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg#xqc3gS1gz1vch7R3RvNebWMjLvBOY-n_14feCYRPsUo"
        }
    }
`

//nolint:lll
const udPresentation = `{
        "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
        "type": ["VerifiablePresentation"],
		"id": "http://example.edu/presentations/1989",
        "verifiableCredential": [{
            "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
            "credentialSchema": [],
            "credentialStatus": {
                "id": "http://issuer.vc.rest.example.com:8070/status/1",
                "type": "CredentialStatusList2017"
            },
            "credentialSubject": {
                "degree": {"degree": "MIT", "type": "BachelorDegree"},
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "name": "Jayden Doe",
                "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
            },
            "id": "https://example.com/credentials/9315d0fd-da93-436e-9e20-2121f2821df3",
            "issuanceDate": "2020-03-16T22:37:26.544Z",
            "issuer": {
                "id": "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg",
                "name": "alice_ca31684e-6cbb-40f9-b7e6-87e1ab5661ae"
            },
            "proof": {
                "created": "2020-04-08T21:19:02Z",
                "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..yGHHYmRp4mWd918SDSzmBDs8eq-SX7WPl8moGB8oJeSqEMmuEiI81D4s5-BPWGmKy3VlCsKJxYrTNqrEGJpNAQ",
                "proofPurpose": "assertionMethod",
                "type": "Ed25519Signature2018",
                "verificationMethod": "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg#xqc3gS1gz1vch7R3RvNebWMjLvBOY-n_14feCYRPsUo"
            },
            "type": ["VerifiableCredential", "UniversityDegreeCredential"]
        }]
    }
`

const noPublicKeyDoc = `{
  "@context": ["https://w3id.org/did/v1","https://w3id.org/did/v2"],
  "id": "did:peer:21tDAKCERh95uGgKbJNHYp"
}`

const vcForDerive = `
	{
	 	"@context": [
	   		"https://www.w3.org/2018/credentials/v1",
	   		"https://w3id.org/citizenship/v1",
	   		"https://w3id.org/security/bbs/v1"
	 	],
	 	"id": "https://issuer.oidp.uscis.gov/credentials/83627465",
	 	"type": [
	   		"VerifiableCredential",
	   		"PermanentResidentCard"
	 	],
	 	"issuer": "did:example:489398593",
	 	"identifier": "83627465",
	 	"name": "Permanent Resident Card",
	 	"description": "Government of Example Permanent Resident Card.",
	 	"issuanceDate": "2019-12-03T12:19:52Z",
	 	"expirationDate": "2029-12-03T12:19:52Z",
	 	"credentialSubject": {
	   		"id": "did:example:b34ca6cd37bbf23",
	   		"type": [
	     		"PermanentResident",
	     		"Person"
	   		],
	   		"givenName": "JOHN",
	   		"familyName": "SMITH",
	   		"gender": "Male",
	   		"image": "data:image/png;base64,iVBORw0KGgokJggg==",
	   		"residentSince": "2015-01-01",
	   		"lprCategory": "C09",
	   		"lprNumber": "999-999-999",
	   		"commuterClassification": "C1",
	   		"birthCountry": "Bahamas",
	   		"birthDate": "1958-07-17"
	 	}
	}
`

const sampleFrame = `
	{
	"@context": [
    	"https://www.w3.org/2018/credentials/v1",
		"https://w3id.org/citizenship/v1",
    	"https://w3id.org/security/bbs/v1"
	],
  	"type": ["VerifiableCredential", "PermanentResidentCard"],
  	"@explicit": true,
  	"identifier": {},
  	"issuer": {},
  	"issuanceDate": {},
  	"credentialSubject": {
    	"@explicit": true,
    	"type": ["PermanentResident", "Person"],
    	"givenName": {},
    	"familyName": {},
    	"gender": {}
  	}
	}
`

const (
	invalidDID = "did:error:123"
	jwsDID     = "did:trustbloc:testnet.trustbloc.local:EiBug_0h2oNJj4Vhk7yrC36HvskhngqTJC46VKS-FDM5fA"
	authDID    = "did:peer:1zQmYEVm9usSN4UdR3bRH2GLzbbcdrzSMEXvgLweekn3yr66"
)

func TestNew(t *testing.T) {
	t.Run("test new command - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		handlers := cmd.GetHandlers()
		require.Equal(t, 14, len(handlers))
	})

	t.Run("test new command - vc store error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("error opening the store"),
			},
		})

		require.Error(t, err)
		require.Contains(t, err.Error(), "new vc store")
		require.Nil(t, cmd)
	})
}

func TestValidateVC(t *testing.T) {
	t.Run("test register - success", func(t *testing.T) {
		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		vcReq := Credential{VerifiableCredential: vc}
		vcReqBytes, err := json.Marshal(vcReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.ValidateCredential(&b, bytes.NewBuffer(vcReqBytes))
		require.NoError(t, err)
	})

	t.Run("test register - invalid request", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		var b bytes.Buffer

		err = cmd.ValidateCredential(&b, bytes.NewBufferString("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	t.Run("test register - validation error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		vcReq := Credential{VerifiableCredential: ""}
		vcReqBytes, err := json.Marshal(vcReq)
		require.NoError(t, err)

		var b bytes.Buffer

		err = cmd.ValidateCredential(&b, bytes.NewBuffer(vcReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "new credential")
	})
}

func TestSaveVC(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	t.Run("test save vc - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		vcReq := CredentialExt{
			Credential: Credential{VerifiableCredential: vc},
			Name:       sampleCredentialName,
		}
		vcReqBytes, err := json.Marshal(vcReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SaveCredential(&b, bytes.NewBuffer(vcReqBytes))
		require.NoError(t, err)
	})

	t.Run("test save vc - invalid request", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		var b bytes.Buffer

		err = cmd.SaveCredential(&b, bytes.NewBufferString("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	t.Run("test save vc - validation error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		vcReq := CredentialExt{
			Credential: Credential{VerifiableCredential: ""},
			Name:       sampleCredentialName,
		}
		vcReqBytes, err := json.Marshal(vcReq)
		require.NoError(t, err)

		var b bytes.Buffer

		err = cmd.SaveCredential(&b, bytes.NewBuffer(vcReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "new credential")
	})

	t.Run("test save vc - store error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				Store: &mockstore.MockStore{
					ErrPut: fmt.Errorf("put error"),
				},
			},
			DocumentLoaderValue: loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		vcReq := CredentialExt{
			Credential: Credential{VerifiableCredential: vc},
			Name:       sampleCredentialName,
		}
		vcReqBytes, err := json.Marshal(vcReq)
		require.NoError(t, err)

		var b bytes.Buffer

		err = cmd.SaveCredential(&b, bytes.NewBuffer(vcReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "save vc")
	})
}

func TestGetVC(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	t.Run("test get vc - success", func(t *testing.T) {
		s := make(map[string]mockstore.DBEntry)
		s["http://example.edu/credentials/1989"] = mockstore.DBEntry{Value: []byte(vc)}

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{"id":"%s"}`, "http://example.edu/credentials/1989")

		var getRW bytes.Buffer
		cmdErr := cmd.GetCredential(&getRW, bytes.NewBufferString(jsoStr))
		require.NoError(t, cmdErr)

		response := Credential{}
		err = json.NewDecoder(&getRW).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.VerifiableCredential)
	})

	t.Run("test get vc - invalid request", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.GetCredential(&b, bytes.NewBufferString("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	t.Run("test get vc - no id in the request", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.GetCredential(&b, bytes.NewBufferString("{}"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential id is mandatory")
	})

	t.Run("test get vc - store error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				Store: &mockstore.MockStore{
					ErrGet: fmt.Errorf("get error"),
				},
			},
			DocumentLoaderValue: loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{"id":"%s"}`, "http://example.edu/credentials/1989")

		var b bytes.Buffer
		err = cmd.GetCredential(&b, bytes.NewBufferString(jsoStr))
		require.Error(t, err)
		require.Contains(t, err.Error(), "get vc")
	})
}

func TestGetCredentialByName(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	t.Run("test get vc by name - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		// save vc with name
		vcReq := CredentialExt{
			Credential: Credential{VerifiableCredential: vc},
			Name:       sampleCredentialName,
		}
		vcReqBytes, err := json.Marshal(vcReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SaveCredential(&b, bytes.NewBuffer(vcReqBytes))
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{"name":"%s"}`, sampleCredentialName)

		var getRW bytes.Buffer
		cmdErr := cmd.GetCredentialByName(&getRW, bytes.NewBufferString(jsoStr))
		require.NoError(t, cmdErr)

		var response verifiablestore.Record
		err = json.NewDecoder(&getRW).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.Equal(t, sampleCredentialName, response.Name)
		require.Equal(t, sampleVCID, response.ID)
	})

	t.Run("test get vc - invalid request", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.GetCredentialByName(&b, bytes.NewBufferString("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	t.Run("test get vc - no name in the request", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := "{}"

		var b bytes.Buffer
		err = cmd.GetCredentialByName(&b, bytes.NewBufferString(jsoStr))
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential name is mandatory")
	})

	t.Run("test get vc - store error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				Store: &mockstore.MockStore{
					ErrGet: fmt.Errorf("get error"),
				},
			},
			DocumentLoaderValue: loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{"name":"%s"}`, sampleCredentialName)

		var b bytes.Buffer
		err = cmd.GetCredentialByName(&b, bytes.NewBufferString(jsoStr))
		require.Error(t, err)
		require.Contains(t, err.Error(), "get vc by name")
	})
}

func TestGetCredentials(t *testing.T) {
	t.Run("test get credentials", func(t *testing.T) {
		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mem.NewProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		// save vc with name
		vcReq := CredentialExt{
			Credential: Credential{VerifiableCredential: vc},
			Name:       sampleCredentialName,
		}
		vcReqBytes, err := json.Marshal(vcReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SaveCredential(&b, bytes.NewBuffer(vcReqBytes))
		require.NoError(t, err)

		var getRW bytes.Buffer
		cmdErr := cmd.GetCredentials(&getRW, nil)
		require.NoError(t, cmdErr)

		var response RecordResult
		err = json.NewDecoder(&getRW).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.Equal(t, 1, len(response.Result))
		require.Len(t, response.Result[0].Context, 2)
		require.Len(t, response.Result[0].Type, 1)
	})
}

func TestGeneratePresentation(t *testing.T) {
	s := make(map[string]mockstore.DBEntry)

	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	cmd, cmdErr := New(&mockprovider.Provider{
		StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
		VDRegistryValue: &mockvdr.MockVDRegistry{
			ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				if didID == invalidDID {
					return nil, errors.New("invalid")
				}

				if didID == jwsDID {
					jwsDoc, err := did.ParseDocument([]byte(jwsDIDDoc))
					if err != nil {
						return nil, errors.New("unmarshal failed ")
					}
					return &did.DocResolution{DIDDocument: jwsDoc}, nil
				}

				didDoc, err := did.ParseDocument([]byte(doc))
				if err != nil {
					return nil, errors.New("unmarshal failed ")
				}
				return &did.DocResolution{DIDDocument: didDoc}, nil
			},
		},
		KMSValue:            &kmsmock.KeyManager{},
		CryptoValue:         &cryptomock.Crypto{},
		DocumentLoaderValue: loader,
	})

	require.NotNil(t, cmd)
	require.NoError(t, cmdErr)

	t.Run("test generate presentation - success", func(t *testing.T) {
		credList := []json.RawMessage{[]byte(vc), []byte(vc)}

		presReq := PresentationRequest{
			VerifiableCredentials: credList,
			DID:                   "did:peer:123456789abcdefghi#inbox",
			ProofOptions:          &ProofOptions{SignatureType: Ed25519Signature2018},
		}
		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.GeneratePresentation(&b, bytes.NewBuffer(presReqBytes))
		require.NoError(t, err)

		// verify response
		var response Presentation
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)

		require.NotEmpty(t, response)
	})

	t.Run("test generate presentation - jws key - success", func(t *testing.T) {
		credList := []json.RawMessage{[]byte(vc), []byte(vc)}

		presReq := PresentationRequest{
			VerifiableCredentials: credList,
			DID:                   jwsDID,
			ProofOptions:          &ProofOptions{SignatureType: Ed25519Signature2018},
		}
		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.GeneratePresentation(&b, bytes.NewBuffer(presReqBytes))
		require.NoError(t, err)

		// verify response
		var response Presentation
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)

		require.NotEmpty(t, response)
		require.Contains(t, string(response.VerifiablePresentation),
			"did:trustbloc:testnet.trustbloc.local:EiBug_0h2oNJj4Vhk7yrC36HvskhngqTJC46VKS-FDM5fA#key-7777")
	})

	t.Run("test generate presentation skip verify - success", func(t *testing.T) {
		credList := []json.RawMessage{[]byte(vcWithDIDNotAvailble), []byte(vcWithDIDNotAvailble)}

		// try with invalid proof
		presReq := PresentationRequest{
			VerifiableCredentials: credList,
			DID:                   "did:peer:123456789abcdefghi#inbox",
			ProofOptions:          &ProofOptions{SignatureType: Ed25519Signature2018},
		}
		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.GeneratePresentation(&b, bytes.NewBuffer(presReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "key-1 is not found for DID did:trustbloc:testnet.trustbloc.local")

		// try by skipping proof check
		presReq.SkipVerify = true
		presReqBytes, err = json.Marshal(presReq)
		require.NoError(t, err)

		var b1 bytes.Buffer
		err = cmd.GeneratePresentation(&b1, bytes.NewBuffer(presReqBytes))
		require.NoError(t, err)
	})

	t.Run("test generate presentation with proof options - success", func(t *testing.T) {
		credList := []json.RawMessage{[]byte(vc), []byte(vc)}

		createdTime := time.Now().AddDate(-1, 0, 0)
		presReq := PresentationRequest{
			VerifiableCredentials: credList,
			DID:                   "did:peer:123456789abcdefghi#inbox",
			ProofOptions: &ProofOptions{
				VerificationMethod: "did:peer:123456789abcdefghi#keys-1",
				Domain:             "issuer.example.com",
				Challenge:          "sample-random-test-value",
				Created:            &createdTime,
				SignatureType:      Ed25519Signature2018,
			},
		}

		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.GeneratePresentation(&b, bytes.NewBuffer(presReqBytes))
		require.NoError(t, err)

		// verify response
		var response Presentation
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)
		require.NotEmpty(t, response)

		vp, err := verifiable.ParsePresentation(response.VerifiablePresentation,
			verifiable.WithPresDisabledProofCheck(),
			verifiable.WithPresJSONLDDocumentLoader(createTestDocumentLoader(t)))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, presReq.DID, vp.Holder)
		require.NotEmpty(t, vp.Proofs)
		require.Len(t, vp.Proofs, 1)
		require.Equal(t, vp.Proofs[0]["challenge"], presReq.Challenge)
		require.Equal(t, vp.Proofs[0]["domain"], presReq.Domain)
		require.Equal(t, vp.Proofs[0]["proofPurpose"], "authentication")
		require.Contains(t, vp.Proofs[0]["created"], strconv.Itoa(presReq.Created.Year()))
	})

	t.Run("test generate presentation with proof options with default vm - success", func(t *testing.T) {
		credList := []json.RawMessage{[]byte(vc), []byte(vc)}

		createdTime := time.Now().AddDate(-1, 0, 0)
		presReq := PresentationRequest{
			VerifiableCredentials: credList,
			DID:                   "did:peer:123456789abcdefghi#inbox",
			ProofOptions: &ProofOptions{
				Domain:        "issuer.example.com",
				Challenge:     "sample-random-test-value",
				Created:       &createdTime,
				SignatureType: Ed25519Signature2018,
			},
		}

		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.GeneratePresentation(&b, bytes.NewBuffer(presReqBytes))
		require.NoError(t, err)

		// verify response
		var response Presentation
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)
		require.NotEmpty(t, response)

		vp, err := verifiable.ParsePresentation(response.VerifiablePresentation,
			verifiable.WithPresDisabledProofCheck(),
			verifiable.WithPresJSONLDDocumentLoader(createTestDocumentLoader(t)))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, presReq.DID, vp.Holder)
		require.NotEmpty(t, vp.Proofs)
		require.Len(t, vp.Proofs, 1)
		require.Equal(t, vp.Proofs[0]["challenge"], presReq.Challenge)
		require.Equal(t, vp.Proofs[0]["domain"], presReq.Domain)
		require.Equal(t, vp.Proofs[0]["proofPurpose"], "authentication")
		require.Contains(t, vp.Proofs[0]["created"], strconv.Itoa(presReq.Created.Year()))
		require.Equal(t, "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ#signing-key",
			vp.Proofs[0]["verificationMethod"])
	})

	t.Run("test generate presentation with proof options - success (p256 jsonwebsignature)", func(t *testing.T) {
		credList := []json.RawMessage{[]byte(vc), []byte(vc)}

		createdTime := time.Now().AddDate(-1, 0, 0)
		presReq := PresentationRequest{
			VerifiableCredentials: credList,
			DID:                   "did:peer:123456789abcdefghi#inbox",
			ProofOptions: &ProofOptions{
				Domain:             "issuer.example.com",
				Challenge:          "sample-random-test-value",
				Created:            &createdTime,
				VerificationMethod: "did:peer:123456789abcdefghi#keys-1",
				SignatureType:      JSONWebSignature2020,
			},
		}

		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.GeneratePresentation(&b, bytes.NewBuffer(presReqBytes))
		require.NoError(t, err)

		// verify response
		var response Presentation
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)
		require.NotEmpty(t, response)

		vp, err := verifiable.ParsePresentation(response.VerifiablePresentation,
			verifiable.WithPresDisabledProofCheck(),
			verifiable.WithPresJSONLDDocumentLoader(createTestDocumentLoader(t)))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, presReq.DID, vp.Holder)
		require.NotEmpty(t, vp.Proofs)
		require.Len(t, vp.Proofs, 1)
		require.Equal(t, vp.Proofs[0]["challenge"], presReq.Challenge)
		require.Equal(t, vp.Proofs[0]["domain"], presReq.Domain)
		require.Equal(t, vp.Proofs[0]["proofPurpose"], "authentication")
		require.Contains(t, vp.Proofs[0]["created"], strconv.Itoa(presReq.Created.Year()))
		require.Contains(t, vp.Proofs[0]["type"], "JsonWebSignature2020")
	})

	t.Run("test generate presentation with proof options - success (ed25519 jsonwebsignature)", func(t *testing.T) {
		credList := []json.RawMessage{[]byte(vc), []byte(vc)}

		createdTime := time.Now().AddDate(-1, 0, 0)
		presReq := PresentationRequest{
			VerifiableCredentials: credList,
			DID:                   jwsDID,
			ProofOptions: &ProofOptions{
				VerificationMethod: "did:trustbloc:testnet.trustbloc.local:EiBug_0h2oNJj4Vhk7yrC36HvskhngqTJC46VKS-FDM5fA#key-7777",
				Domain:             "issuer.example.com",
				Challenge:          "sample-random-test-value",
				Created:            &createdTime,
				SignatureType:      JSONWebSignature2020,
			},
		}

		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.GeneratePresentation(&b, bytes.NewBuffer(presReqBytes))
		require.NoError(t, err)

		// verify response
		var response Presentation
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)
		require.NotEmpty(t, response)

		vp, err := verifiable.ParsePresentation(response.VerifiablePresentation,
			verifiable.WithPresDisabledProofCheck(),
			verifiable.WithPresJSONLDDocumentLoader(createTestDocumentLoader(t)))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.NotEmpty(t, vp.Proofs)
		require.Len(t, vp.Proofs, 1)
		require.Equal(t, vp.Proofs[0]["challenge"], presReq.Challenge)
		require.Equal(t, vp.Proofs[0]["domain"], presReq.Domain)
		require.Equal(t, vp.Proofs[0]["proofPurpose"], "authentication")
		require.Contains(t, vp.Proofs[0]["created"], strconv.Itoa(presReq.Created.Year()))
		require.Contains(t, vp.Proofs[0]["type"], "JsonWebSignature2020")
	})

	t.Run("test generate presentation with proof options - unsupported signature type", func(t *testing.T) {
		credList := []json.RawMessage{[]byte(vc), []byte(vc)}

		presReq := PresentationRequest{
			VerifiableCredentials: credList,
			DID:                   "did:peer:123456789abcdefghi#inbox",
			ProofOptions: &ProofOptions{
				VerificationMethod: "did:peer:123456789abcdefghi#keys-1",
				SignatureType:      "invalid",
			},
		}

		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.GeneratePresentation(&b, bytes.NewBuffer(presReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature type unsupported invalid")
	})

	t.Run("test generate presentation with proof options - signature type empty", func(t *testing.T) {
		credList := []json.RawMessage{[]byte(vc), []byte(vc)}

		presReq := PresentationRequest{
			VerifiableCredentials: credList,
			DID:                   "did:peer:123456789abcdefghi#inbox",
			ProofOptions:          &ProofOptions{Domain: "domain"},
		}

		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.GeneratePresentation(&b, bytes.NewBuffer(presReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature type empty")
	})

	t.Run("test generate verifiable presentation with proof options & presentation - success", func(t *testing.T) {
		pRaw := json.RawMessage(`{"@context": "https://www.w3.org/2018/credentials/v1",
		"type": "VerifiablePresentation"}`)

		createdTime := time.Now().AddDate(-1, 0, 0)
		presReq := PresentationRequest{
			Presentation: pRaw,
			DID:          "did:peer:123456789abcdefghi#inbox",
			ProofOptions: &ProofOptions{
				VerificationMethod: "did:peer:123456789abcdefghi#keys-1",
				Domain:             "issuer.example.com",
				Challenge:          "sample-random-test-value",
				Created:            &createdTime,
				SignatureType:      JSONWebSignature2020,
			},
		}

		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.GeneratePresentation(&b, bytes.NewBuffer(presReqBytes))
		require.NoError(t, err)

		// verify response
		var response Presentation
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)
		require.NotEmpty(t, response)

		vp, err := verifiable.ParsePresentation(response.VerifiablePresentation,
			verifiable.WithPresDisabledProofCheck(),
			verifiable.WithPresJSONLDDocumentLoader(createTestDocumentLoader(t)))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Empty(t, vp.Credentials())
		require.NotEmpty(t, vp.Proofs)
		require.Equal(t, vp.Holder, "did:peer:123456789abcdefghi#inbox")
		require.Len(t, vp.Proofs, 1)
		require.Equal(t, vp.Proofs[0]["challenge"], presReq.Challenge)
		require.Equal(t, vp.Proofs[0]["domain"], presReq.Domain)
		require.Equal(t, vp.Proofs[0]["proofPurpose"], "authentication")
		require.Contains(t, vp.Proofs[0]["created"], strconv.Itoa(presReq.Created.Year()))
	})

	t.Run("test generate presentation - invalid request", func(t *testing.T) {
		var b bytes.Buffer

		err := cmd.GeneratePresentation(&b, bytes.NewBufferString("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	t.Run("test generate presentation - validation error", func(t *testing.T) {
		credList := []json.RawMessage{[]byte("{}")}

		presReq := PresentationRequest{
			VerifiableCredentials: credList,
			DID:                   "did:peer:123456789abcdefghi#inbox",
			ProofOptions:          &ProofOptions{SignatureType: Ed25519Signature2018},
		}
		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		var b bytes.Buffer

		err = cmd.GeneratePresentation(&b, bytes.NewBuffer(presReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "generate vp - parse presentation request")
	})

	t.Run("test generate presentation - failed to sign presentation", func(t *testing.T) {
		require.NotNil(t, cmd)
		require.NoError(t, cmdErr)

		credList := []json.RawMessage{[]byte(vc)}

		presReq := PresentationRequest{
			VerifiableCredentials: credList,
			DID:                   "did:error:123",
		}
		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		var b bytes.Buffer

		err = cmd.GeneratePresentation(&b, bytes.NewBuffer(presReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "generate vp - failed to get did doc from store or vdr")
	})
}

func TestGeneratePresentationByID(t *testing.T) {
	s := make(map[string]mockstore.DBEntry)

	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	cmd, cmdErr := New(&mockprovider.Provider{
		StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
		VDRegistryValue: &mockvdr.MockVDRegistry{
			ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				if didID == invalidDID {
					return nil, errors.New("invalid")
				}
				didDoc, err := did.ParseDocument([]byte(doc))
				if err != nil {
					return nil, errors.New("unmarshal failed ")
				}
				return &did.DocResolution{DIDDocument: didDoc}, nil
			},
		},
		KMSValue:            &kmsmock.KeyManager{},
		CryptoValue:         &cryptomock.Crypto{},
		DocumentLoaderValue: loader,
	})
	require.NotNil(t, cmd)
	require.NoError(t, cmdErr)

	t.Run("test generate presentation - success", func(t *testing.T) {
		s["http://example.edu/credentials/1989"] = mockstore.DBEntry{Value: []byte(vc)}
		s["did:peer:21tDAKCERh95uGgKbJNHYp"] = mockstore.DBEntry{Value: []byte(doc)}

		presIDArgs := PresentationRequestByID{
			ID:            "http://example.edu/credentials/1989",
			DID:           "did:peer:21tDAKCERh95uGgKbJNHYp",
			SignatureType: Ed25519Signature2018,
		}
		presReqBytes, e := json.Marshal(presIDArgs)
		require.NoError(t, e)

		var getRW bytes.Buffer
		cmdErr := cmd.GeneratePresentationByID(&getRW, bytes.NewBuffer(presReqBytes))
		require.NoError(t, cmdErr)

		response := Presentation{}
		err := json.NewDecoder(&getRW).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.VerifiablePresentation)
	})

	t.Run("test generate presentation - failed to get did doc", func(t *testing.T) {
		s["http://example.edu/credentials/1989"] = mockstore.DBEntry{Value: []byte(vc)}
		s["did:peer:21tDAKCERh95uGgKbJNHYp"] = mockstore.DBEntry{Value: []byte(doc)}

		presIDArgs := PresentationRequestByID{
			ID:            "http://example.edu/credentials/1989",
			DID:           "did:error:123",
			SignatureType: Ed25519Signature2018,
		}
		presReqBytes, e := json.Marshal(presIDArgs)
		require.NoError(t, e)

		var b bytes.Buffer
		err := cmd.GeneratePresentationByID(&b, bytes.NewBuffer(presReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "generate vp by id - failed to get did doc from store or vdr")
	})

	t.Run("test generate presentation - invalid request", func(t *testing.T) {
		var b bytes.Buffer
		err := cmd.GeneratePresentationByID(&b, bytes.NewBufferString("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	t.Run("test generate presentation - no id in the request", func(t *testing.T) {
		jsoStr := "{}"

		var b bytes.Buffer
		err := cmd.GeneratePresentationByID(&b, bytes.NewBufferString(jsoStr))
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential id is mandatory")
	})

	t.Run("test generate presentation - no did in the request", func(t *testing.T) {
		jsoStr := fmt.Sprintf(`{"id":"%s"}`, "http://example.edu/credentials/1989")

		var b bytes.Buffer
		err := cmd.GeneratePresentationByID(&b, bytes.NewBufferString(jsoStr))
		require.Error(t, err)
		require.Contains(t, err.Error(), "did is mandatory")
	})

	t.Run("test generate presentation - store error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				Store: &mockstore.MockStore{
					ErrGet: fmt.Errorf("get error"),
				},
			},
		})

		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{"id":"%s","did":"%s"}`, "http://example.edu/credentials/1989",
			"did:peer:21tDAKCERh95uGgKbJNHYp")

		var b bytes.Buffer
		err = cmd.GeneratePresentationByID(&b, bytes.NewBufferString(jsoStr))
		require.Error(t, err)
		require.Contains(t, err.Error(), "get vc")
	})
}

func TestGeneratePresentationHelperFunctions(t *testing.T) {
	s := make(map[string]mockstore.DBEntry)

	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	cmd, cmdErr := New(&mockprovider.Provider{
		StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
		VDRegistryValue: &mockvdr.MockVDRegistry{
			ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				if didID == invalidDID {
					return nil, errors.New("invalid")
				}
				didDoc, err := did.ParseDocument([]byte(doc))
				if err != nil {
					return nil, errors.New("unmarshal failed ")
				}
				return &did.DocResolution{DIDDocument: didDoc}, nil
			},
		},
		KMSValue:            &kmsmock.KeyManager{},
		DocumentLoaderValue: loader,
	})
	require.NotNil(t, cmd)
	require.NoError(t, cmdErr)

	t.Run("test generate presentation by id helper- error", func(t *testing.T) {
		cred := &verifiable.Credential{}
		err := json.Unmarshal([]byte(vc), cred)
		require.NoError(t, err)

		doc, err := did.ParseDocument([]byte(invalidDoc))
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.generatePresentationByID(&b, cred, doc, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "prepare vp by id: public key not found in DID Document")
	})

	t.Run("test create and sign presentation - error", func(t *testing.T) {
		cred := &verifiable.Credential{}
		err := json.Unmarshal([]byte(vc), cred)
		require.NoError(t, err)

		doc, err := did.ParseDocument([]byte(noPublicKeyDoc))
		require.NoError(t, err)

		vp, err := cmd.createAndSignPresentationByID(cred, doc, "")
		require.Error(t, err)
		require.Nil(t, vp)
		require.Contains(t, err.Error(), "public key not found in DID Document")
	})

	t.Run("test generate presentation helper parse presentation- no credential error", func(t *testing.T) {
		credList := make([]json.RawMessage, 0)

		req := &PresentationRequest{
			ProofOptions:          &ProofOptions{SignatureType: Ed25519Signature2018},
			VerifiableCredentials: credList,
		}

		vc, p, _, err := cmd.parsePresentationRequest(req, nil)
		require.Error(t, err)
		require.Nil(t, vc)
		require.Nil(t, p)
		require.Contains(t, err.Error(), "no valid credentials/presentation found")
	})

	t.Run("parse credentials- public key not found in DID Document", func(t *testing.T) {
		credList := []json.RawMessage{[]byte(vc)}

		req := &PresentationRequest{
			VerifiableCredentials: credList,
			ProofOptions:          &ProofOptions{SignatureType: Ed25519Signature2018},
		}

		doc, err := did.ParseDocument([]byte(noPublicKeyDoc))
		require.NoError(t, err)

		vc, p, opts, err := cmd.parsePresentationRequest(req, doc)
		require.Error(t, err)
		require.Nil(t, vc)
		require.Nil(t, p)
		require.Nil(t, opts)
		require.Contains(t, err.Error(), "public key not found in DID Document")
	})

	t.Run("parse presentation - public key not found in DID Document", func(t *testing.T) {
		req := &PresentationRequest{
			Presentation: stringToJSONRaw(udPresentation),
			ProofOptions: &ProofOptions{SignatureType: Ed25519Signature2018},
		}

		doc, err := did.ParseDocument([]byte(noPublicKeyDoc))
		require.NoError(t, err)

		vc, p, opts, err := cmd.parsePresentationRequest(req, doc)
		require.Error(t, err)
		require.Nil(t, vc)
		require.Nil(t, p)
		require.Nil(t, opts)
		require.Contains(t, err.Error(), "public key not found in DID Document")
	})

	t.Run("parse presentation - failed", func(t *testing.T) {
		req := &PresentationRequest{
			Presentation: []byte(`[]`),
			ProofOptions: &ProofOptions{SignatureType: Ed25519Signature2018},
		}

		doc, err := did.ParseDocument([]byte(noPublicKeyDoc))
		require.NoError(t, err)

		vc, p, opts, err := cmd.parsePresentationRequest(req, doc)
		require.Error(t, err)
		require.Nil(t, vc)
		require.Nil(t, p)
		require.Nil(t, opts)
		require.Contains(t, err.Error(), "parse presentation failed")
	})

	t.Run("test parse presentation- public key not found in DID Document", func(t *testing.T) {
		credList := []json.RawMessage{[]byte(vc)}

		req := &PresentationRequest{
			VerifiableCredentials: credList,
			ProofOptions:          &ProofOptions{SignatureType: Ed25519Signature2018},
		}

		doc, err := did.ParseDocument([]byte(noPublicKeyDoc))
		require.NoError(t, err)

		require.NoError(t, err)

		vc, p, opts, err := cmd.parsePresentationRequest(req, doc)
		require.Error(t, err)
		require.Nil(t, vc)
		require.Nil(t, p)
		require.Nil(t, opts)
		require.Contains(t, err.Error(), "public key not found in DID Document")
	})

	t.Run("test parse presentation- invalid vc", func(t *testing.T) {
		credList := []json.RawMessage{[]byte(invalidVC)}

		req := &PresentationRequest{
			VerifiableCredentials: credList,
			ProofOptions:          &ProofOptions{SignatureType: Ed25519Signature2018},
		}

		vc, p, opts, err := cmd.parsePresentationRequest(req, nil)
		require.Error(t, err)
		require.Nil(t, vc)
		require.Nil(t, p)
		require.Nil(t, opts)
		require.Contains(t, err.Error(), "parse credential failed: build new credential")
	})

	t.Run("test create and sign presentation by id - error", func(t *testing.T) {
		cmd, cmdErr := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			VDRegistryValue: &mockvdr.MockVDRegistry{
				ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
					if didID == invalidDID {
						return nil, errors.New("invalid")
					}
					didDoc, err := did.ParseDocument([]byte(doc))
					if err != nil {
						return nil, errors.New("unmarshal failed ")
					}
					return &did.DocResolution{DIDDocument: didDoc}, nil
				},
			},
			KMSValue:            &kmsmock.KeyManager{},
			CryptoValue:         &cryptomock.Crypto{SignErr: errors.New("invalid signer")},
			DocumentLoaderValue: loader,
		})

		cred := &verifiable.Credential{}
		err := json.Unmarshal([]byte(vc), cred)
		require.NoError(t, err)

		d, err := did.ParseDocument([]byte(doc))
		require.NoError(t, err)

		require.NotNil(t, cmd)
		require.NoError(t, cmdErr)

		vp, err := cmd.createAndSignPresentationByID(cred, d, Ed25519Signature2018)
		require.Error(t, err)
		require.Nil(t, vp)
		require.Contains(t, err.Error(), "failed to sign vp by ID: failed to add linked data proof: add linked data proof")
	})
}

func TestSaveVP(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	t.Run("test save vp - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		vpReq := PresentationExt{
			Presentation: Presentation{VerifiablePresentation: stringToJSONRaw(udPresentation)},
			Name:         samplePresentationName,
		}
		vpReqBytes, err := json.Marshal(vpReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SavePresentation(&b, bytes.NewBuffer(vpReqBytes))
		require.NoError(t, err)

		vpReq = PresentationExt{
			Presentation: Presentation{VerifiablePresentation: stringToJSONRaw(udVerifiablePresentation)},
			Name:         samplePresentationName + "_x",
		}

		vpReqBytes, err = json.Marshal(vpReq)
		require.NoError(t, err)

		var b1 bytes.Buffer
		err = cmd.SavePresentation(&b1, bytes.NewBuffer(vpReqBytes))
		require.NoError(t, err)

		vpReq = PresentationExt{
			Presentation: Presentation{VerifiablePresentation: stringToJSONRaw(udPresentation)},
			Name:         samplePresentationName,
		}
		vpReqBytes, err = json.Marshal(vpReq)
		require.NoError(t, err)

		var b2 bytes.Buffer
		err = cmd.SavePresentation(&b2, bytes.NewBuffer(vpReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "presentation name already exists")
	})

	t.Run("test save vp - invalid request", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		var b bytes.Buffer

		err = cmd.SavePresentation(&b, bytes.NewBufferString("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	t.Run("test save vp - validation error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		vcReq := PresentationExt{
			Presentation: Presentation{VerifiablePresentation: stringToJSONRaw("{}")},
			Name:         samplePresentationName,
		}
		vcReqBytes, err := json.Marshal(vcReq)
		require.NoError(t, err)

		var b bytes.Buffer

		err = cmd.SavePresentation(&b, bytes.NewBuffer(vcReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "verifiable presentation is not valid")

		vcReq = PresentationExt{
			Presentation: Presentation{VerifiablePresentation: stringToJSONRaw("{}")},
			Name:         "",
		}
		vcReqBytes, err = json.Marshal(vcReq)
		require.NoError(t, err)

		var b1 bytes.Buffer

		err = cmd.SavePresentation(&b1, bytes.NewBuffer(vcReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "presentation name is mandatory")
	})

	t.Run("test save vc - store error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				Store: &mockstore.MockStore{
					ErrPut: fmt.Errorf("put error"),
				},
			},
			DocumentLoaderValue: loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		vcReq := PresentationExt{
			Presentation: Presentation{VerifiablePresentation: stringToJSONRaw(udPresentation)},
			Name:         samplePresentationName,
		}
		vcReqBytes, err := json.Marshal(vcReq)
		require.NoError(t, err)

		var b bytes.Buffer

		err = cmd.SavePresentation(&b, bytes.NewBuffer(vcReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "save vp : failed to put vp:")
	})
}

func TestGetVP(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	t.Run("test get vp - success", func(t *testing.T) {
		s := make(map[string]mockstore.DBEntry)
		s["http://example.edu/presentations/1989"] = mockstore.DBEntry{Value: []byte(vc)}

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		// save presentation
		vpReq := PresentationExt{
			Presentation: Presentation{VerifiablePresentation: stringToJSONRaw(udPresentation)},
			Name:         samplePresentationName,
		}
		vpReqBytes, err := json.Marshal(vpReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SavePresentation(&b, bytes.NewBuffer(vpReqBytes))
		require.NoError(t, err)

		jsoStr := `{"id":"http://example.edu/presentations/1989"}`

		var getRW bytes.Buffer
		cmdErr := cmd.GetPresentation(&getRW, bytes.NewBufferString(jsoStr))
		require.NoError(t, cmdErr)

		response := Presentation{}
		err = json.NewDecoder(&getRW).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.VerifiablePresentation)
	})

	t.Run("test get vp - invalid request", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.GetPresentation(&b, bytes.NewBufferString("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	t.Run("test get vp - no id in the request", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := "{}"

		var b bytes.Buffer
		err = cmd.GetPresentation(&b, bytes.NewBufferString(jsoStr))
		require.Error(t, err)
		require.Contains(t, err.Error(), "presentation id is mandatory")
	})

	t.Run("test get vp - store error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				Store: &mockstore.MockStore{
					ErrGet: fmt.Errorf("get error"),
				},
			},
			DocumentLoaderValue: loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := `{"id":"http://example.edu/presentations/1989"}`

		var b bytes.Buffer
		err = cmd.GetPresentation(&b, bytes.NewBufferString(jsoStr))
		require.Error(t, err)
		require.Contains(t, err.Error(), "get vp")
	})
}

func TestGetPresentations(t *testing.T) {
	t.Run("test get credentials", func(t *testing.T) {
		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mem.NewProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		// save presentation
		vpReq := PresentationExt{
			Presentation: Presentation{VerifiablePresentation: stringToJSONRaw(udPresentation)},
			Name:         samplePresentationName,
		}
		vpReqBytes, err := json.Marshal(vpReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SavePresentation(&b, bytes.NewBuffer(vpReqBytes))
		require.NoError(t, err)

		var getRW bytes.Buffer
		cmdErr := cmd.GetPresentations(&getRW, nil)
		require.NoError(t, cmdErr)

		var response RecordResult
		err = json.NewDecoder(&getRW).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.Len(t, response.Result, 1)
		require.Len(t, response.Result[0].Context, 2)
		require.Len(t, response.Result[0].Type, 1)
	})
}

func TestGeneratePresentation_prepareOpts(t *testing.T) {
	dids := []string{doc, didKeyDoc, tbDoc, invalidDoc, tbDocNoAuth}

	didStore := make(map[string]*did.Doc)

	for _, d := range dids {
		doc, err := did.ParseDocument([]byte(d))
		require.NoError(t, err)
		require.NotNil(t, doc)

		didStore[doc.ID] = doc
	}

	require.Len(t, didStore, len(dids))

	testPrepareOpts := func(method did.VerificationRelationship) {
		//nolint:lll
		t.Run("Test generate presentation opts", func(t *testing.T) {
			tests := []struct {
				name         string
				requestDID   string
				requestOpts  *ProofOptions
				responseOpts *ProofOptions
				err          string
			}{
				{
					name:        "with default opts",
					requestDID:  "did:peer:123456789abcdefghi#inbox",
					requestOpts: nil,
					responseOpts: &ProofOptions{
						VerificationMethod: "did:peer:123456789abcdefghi#keys-1",
						proofPurpose:       "authentication",
					},
				},
				{
					name:       "with default opts when there are two authentication methods in DID",
					requestDID: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
					requestOpts: &ProofOptions{
						VerificationMethod: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
					},
					responseOpts: &ProofOptions{
						VerificationMethod: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
						proofPurpose:       "authentication",
					},
				},
				{
					name:       "second under authentication as verification method",
					requestDID: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
					requestOpts: &ProofOptions{
						VerificationMethod: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#XiRjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
					},
					responseOpts: &ProofOptions{
						VerificationMethod: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#XiRjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
						proofPurpose:       "authentication",
					},
				},
				{
					name:       "first under authentication as verification method",
					requestDID: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
					requestOpts: &ProofOptions{
						VerificationMethod: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
					},
					responseOpts: &ProofOptions{
						VerificationMethod: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
						proofPurpose:       "authentication",
					},
				},
				{
					name:       "first with only one authentication method",
					requestDID: "did:trustbloc:testnet.trustbloc.local:EiAzdTbGPXhvC0ESOcnlR7nCWkN1m1XUJ04uEG9ayhRbPg",
					requestOpts: &ProofOptions{
						VerificationMethod: "did:trustbloc:testnet.trustbloc.local:EiAzdTbGPXhvC0ESOcnlR7nCWkN1m1XUJ04uEG9ayhRbPg#bG9jYWwtbG9jazovL2RlZmF1bHQvbWFzdGVyL2tleS96cThTc3JJZ0JVTHhveU9XU2tLZ2drQWJhcjJhVDVHTmlXbERuY244VlYwPQ",
					},
					responseOpts: &ProofOptions{
						VerificationMethod: "did:trustbloc:testnet.trustbloc.local:EiAzdTbGPXhvC0ESOcnlR7nCWkN1m1XUJ04uEG9ayhRbPg#bG9jYWwtbG9jazovL2RlZmF1bHQvbWFzdGVyL2tleS96cThTc3JJZ0JVTHhveU9XU2tLZ2drQWJhcjJhVDVHTmlXbERuY244VlYwPQ",
						proofPurpose:       "authentication",
					},
				},
				{
					name:       "did without authentication method but VM in opts",
					requestDID: "did:trustbloc:testnet.trustbloc.local:EiAzdTbGPXhvC0ESOcnlR7nCWkN1m1XUJ04uEG9ayhRbPg1",
					requestOpts: &ProofOptions{
						VerificationMethod: "did:trustbloc:testnet.trustbloc.local:EiAzdTbGPXhvC0ESOcnlR7nCWkN1m1XUJ04uEG9ayhRbPg1#bG9jYWwtbG9jazovL2RlZmF1bHQvbWFzdGVyL2tleS96cThTc3JJZ0JVTHhveU9XU2tLZ2drQWJhcjJhVDVHTmlXbERuY244VlYwPQ",
					},
					err: "unable to find matching 'authentication' key IDs for given verification method",
				},
				{
					name:        "did without authentication method but no VM in opts",
					requestDID:  "did:trustbloc:testnet.trustbloc.local:EiAzdTbGPXhvC0ESOcnlR7nCWkN1m1XUJ04uEG9ayhRbPg1",
					requestOpts: &ProofOptions{},
					responseOpts: &ProofOptions{
						VerificationMethod: "did:trustbloc:testnet.trustbloc.local:EiAzdTbGPXhvC0ESOcnlR7nCWkN1m1XUJ04uEG9ayhRbPg1#bG9jYWwtbG9jazovL2RlZmF1bHQvbWFzdGVyL2tleS96cThTc3JJZ0JVTHhveU9XU2tLZ2drQWJhcjJhVDVHTmlXbERuY244VlYwPQ",
						proofPurpose:       "authentication",
					},
				},
				{
					name:        "using invalid DID and default opts",
					requestDID:  "did:peer:21tDAKCERh95uGgKbJNHYp",
					requestOpts: &ProofOptions{},
					err:         "failed to get default verification method: public key not found in DID Document",
				},
				{
					name:       "using invalid DID and verification method",
					requestDID: "did:peer:21tDAKCERh95uGgKbJNHYp",
					requestOpts: &ProofOptions{
						VerificationMethod: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
					},
					err: "unable to find matching 'authentication' key IDs for given verification method",
				},
				{
					name:       "private key matching second verification method",
					requestDID: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
					requestOpts: &ProofOptions{
						VerificationMethod: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#XiRjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
					},
					responseOpts: &ProofOptions{
						VerificationMethod: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#XiRjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
						proofPurpose:       "authentication",
					},
				},
				{
					name:       "private key matching first verification method",
					requestDID: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
					requestOpts: &ProofOptions{
						VerificationMethod: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
					},
					responseOpts: &ProofOptions{
						VerificationMethod: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
						proofPurpose:       "authentication",
					},
				},
				{
					name:       "private key not matching any verification method",
					requestDID: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
					requestOpts: &ProofOptions{
						VerificationMethod: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#XiRjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHdXYZ",
					},
					err: "unable to find matching 'authentication' key IDs for given verification method",
				},
				{
					name:       "all opts given",
					requestDID: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
					requestOpts: &ProofOptions{
						VerificationMethod: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#XiRjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
						Domain:             "sample.domain.example.com",
						Challenge:          "sample-challenge",
						SignatureType:      JSONWebSignature2020,
					},
					responseOpts: &ProofOptions{
						VerificationMethod: "did:key:z6MkjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd#XiRjRagNiMu91DduvCvgEsqLZDVzrJzFrwahc4tXLt9DoHd",
						proofPurpose:       "authentication",
						Domain:             "sample.domain.example.com",
						Challenge:          "sample-challenge",
						SignatureType:      JSONWebSignature2020,
					},
				},
			}

			t.Parallel()

			for _, test := range tests {
				tc := test
				t.Run(tc.name, func(t *testing.T) {
					res, err := prepareOpts(tc.requestOpts, didStore[tc.requestDID], method)

					if tc.err != "" {
						require.Error(t, err)
						require.Contains(t, err.Error(), tc.err)
						require.Nil(t, res)

						return
					}

					require.NoError(t, err)
					require.NotNil(t, res)
					require.Equal(t, tc.responseOpts, res)
				})
			}
		})
	}

	testPrepareOpts(did.Authentication)
}

func TestCommand_SignCredential(t *testing.T) {
	s := make(map[string]mockstore.DBEntry)

	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	cmd, cmdErr := New(&mockprovider.Provider{
		StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
		VDRegistryValue: &mockvdr.MockVDRegistry{
			ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				if didID == invalidDID {
					return nil, errors.New("invalid")
				}

				if didID == jwsDID {
					jwsDoc, err := did.ParseDocument([]byte(jwsDIDDoc))
					if err != nil {
						return nil, errors.New("unmarshal failed ")
					}
					return &did.DocResolution{DIDDocument: jwsDoc}, nil
				}

				if didID == authDID {
					authDoc, err := did.ParseDocument([]byte(authDoc))
					if err != nil {
						return nil, errors.New("unmarshal failed ")
					}
					return &did.DocResolution{DIDDocument: authDoc}, nil
				}

				didDoc, err := did.ParseDocument([]byte(doc))
				if err != nil {
					return nil, errors.New("unmarshal failed ")
				}
				return &did.DocResolution{DIDDocument: didDoc}, nil
			},
		},
		KMSValue:            &kmsmock.KeyManager{},
		CryptoValue:         &cryptomock.Crypto{},
		DocumentLoaderValue: loader,
	})

	require.NotNil(t, cmd)
	require.NoError(t, cmdErr)

	t.Run("test sign credential - success", func(t *testing.T) {
		req := SignCredentialRequest{
			Credential:   []byte(vc),
			DID:          "did:peer:123456789abcdefghi#inbox",
			ProofOptions: &ProofOptions{SignatureType: Ed25519Signature2018},
		}
		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SignCredential(&b, bytes.NewBuffer(reqBytes))
		require.NoError(t, err)

		// verify response
		var response SignCredentialResponse
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)

		require.NotEmpty(t, response)
	})

	t.Run("test sign auth credential - success", func(t *testing.T) {
		req := SignCredentialRequest{
			Credential:   []byte(authVC),
			DID:          "did:peer:1zQmYEVm9usSN4UdR3bRH2GLzbbcdrzSMEXvgLweekn3yr66",
			ProofOptions: &ProofOptions{SignatureType: Ed25519Signature2018},
		}
		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SignCredential(&b, bytes.NewBuffer(reqBytes))
		require.NoError(t, err)

		// verify response
		var response SignCredentialResponse
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)

		require.NotEmpty(t, response)
	})

	t.Run("test sign credential - jws key - success", func(t *testing.T) {
		req := SignCredentialRequest{
			Credential:   []byte(vc),
			DID:          jwsDID,
			ProofOptions: &ProofOptions{SignatureType: Ed25519Signature2018},
		}
		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SignCredential(&b, bytes.NewBuffer(reqBytes))
		require.NoError(t, err)

		// verify response
		var response SignCredentialResponse
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)

		require.NotEmpty(t, response)
		require.Contains(t, string(response.VerifiableCredential),
			"did:trustbloc:testnet.trustbloc.local:EiBug_0h2oNJj4Vhk7yrC36HvskhngqTJC46VKS-FDM5fA#key-7777")
	})

	t.Run("test sign credential with proof options - success", func(t *testing.T) {
		createdTime := time.Now().AddDate(-1, 0, 0)
		req := SignCredentialRequest{
			Credential: []byte(vc),
			DID:        "did:peer:123456789abcdefghi#inbox",
			ProofOptions: &ProofOptions{
				VerificationMethod: "did:peer:123456789abcdefghi#keys-1",
				Domain:             "issuer.example.com",
				Challenge:          "sample-random-test-value",
				Created:            &createdTime,
				SignatureType:      Ed25519Signature2018,
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SignCredential(&b, bytes.NewBuffer(reqBytes))
		require.NoError(t, err)

		// verify response
		var response SignCredentialResponse
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)
		require.NotEmpty(t, response)

		vc, err := verifiable.ParseCredential(response.VerifiableCredential, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(loader))

		require.NoError(t, err)
		require.NotNil(t, vc)
		require.NotEmpty(t, vc.Proofs)
		require.Len(t, vc.Proofs, 1)
		require.Equal(t, vc.Proofs[0]["challenge"], req.Challenge)
		require.Equal(t, vc.Proofs[0]["domain"], req.Domain)
		require.Equal(t, vc.Proofs[0]["proofPurpose"], "assertionMethod")
		require.Contains(t, vc.Proofs[0]["created"], strconv.Itoa(req.Created.Year()))
	})

	t.Run("test sign credential with proof options with default vm - success", func(t *testing.T) {
		createdTime := time.Now().AddDate(-1, 0, 0)
		req := SignCredentialRequest{
			Credential: []byte(vc),
			DID:        "did:peer:123456789abcdefghi#inbox",
			ProofOptions: &ProofOptions{
				Domain:        "issuer.example.com",
				Challenge:     "sample-random-test-value",
				Created:       &createdTime,
				SignatureType: Ed25519Signature2018,
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SignCredential(&b, bytes.NewBuffer(reqBytes))
		require.NoError(t, err)

		// verify response
		var response SignCredentialResponse
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)
		require.NotEmpty(t, response)

		vp, err := verifiable.ParseCredential(response.VerifiableCredential, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(loader))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.NotEmpty(t, vp.Proofs)
		require.Len(t, vp.Proofs, 1)
		require.Equal(t, vp.Proofs[0]["challenge"], req.Challenge)
		require.Equal(t, vp.Proofs[0]["domain"], req.Domain)
		require.Equal(t, vp.Proofs[0]["proofPurpose"], "assertionMethod")
		require.Contains(t, vp.Proofs[0]["created"], strconv.Itoa(req.Created.Year()))
		require.Equal(t, "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ#signing-key",
			vp.Proofs[0]["verificationMethod"])
	})

	t.Run("test sign credential with proof options - success (p256 jsonwebsignature)", func(t *testing.T) {
		createdTime := time.Now().AddDate(-1, 0, 0)
		req := SignCredentialRequest{
			Credential: []byte(vc),
			DID:        "did:peer:123456789abcdefghi#inbox",
			ProofOptions: &ProofOptions{
				Domain:             "issuer.example.com",
				Challenge:          "sample-random-test-value",
				Created:            &createdTime,
				VerificationMethod: "did:peer:123456789abcdefghi#keys-1",
				SignatureType:      JSONWebSignature2020,
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SignCredential(&b, bytes.NewBuffer(reqBytes))
		require.NoError(t, err)

		// verify response
		var response SignCredentialResponse
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)
		require.NotEmpty(t, response)

		vc, err := verifiable.ParseCredential(response.VerifiableCredential, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(loader))

		require.NoError(t, err)
		require.NotNil(t, vc)
		require.NotEmpty(t, vc.Proofs)
		require.Len(t, vc.Proofs, 1)
		require.Equal(t, vc.Proofs[0]["challenge"], req.Challenge)
		require.Equal(t, vc.Proofs[0]["domain"], req.Domain)
		require.Equal(t, vc.Proofs[0]["proofPurpose"], "assertionMethod")
		require.Contains(t, vc.Proofs[0]["created"], strconv.Itoa(req.Created.Year()))
		require.Contains(t, vc.Proofs[0]["type"], "JsonWebSignature2020")
	})

	t.Run("test sign credential with proof options - success (BbsBlsSignature2020)", func(t *testing.T) {
		createdTime := time.Now().AddDate(-1, 0, 0)
		signatureRepresentation := verifiable.SignatureProofValue

		req := SignCredentialRequest{
			Credential: []byte(bbsVc),
			ProofOptions: &ProofOptions{
				Domain:                  "issuer.example.com",
				Challenge:               "sample-random-test-value",
				SignatureRepresentation: &signatureRepresentation,
				Created:                 &createdTime,
				SignatureType:           BbsBlsSignature2020,
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SignCredential(&b, bytes.NewBuffer(reqBytes))
		require.NoError(t, err)

		// verify response
		var response SignCredentialResponse
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)
		require.NotEmpty(t, response)

		vc, err := verifiable.ParseCredential(response.VerifiableCredential, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(loader))

		require.NoError(t, err)
		require.NotNil(t, vc)
		require.NotEmpty(t, vc.Proofs)
		require.Len(t, vc.Proofs, 1)
		require.Equal(t, vc.Proofs[0]["challenge"], req.Challenge)
		require.Equal(t, vc.Proofs[0]["domain"], req.Domain)
		require.Equal(t, vc.Proofs[0]["proofPurpose"], "assertionMethod")
		require.Contains(t, vc.Proofs[0]["created"], strconv.Itoa(req.Created.Year()))
		require.Contains(t, vc.Proofs[0]["type"], "BbsBlsSignature2020")
	})

	t.Run("test sign credential with proof options - success (ed25519 jsonwebsignature)", func(t *testing.T) {
		createdTime := time.Now().AddDate(-1, 0, 0)
		req := SignCredentialRequest{
			Credential: []byte(vc),
			DID:        jwsDID,
			ProofOptions: &ProofOptions{
				VerificationMethod: "did:trustbloc:testnet.trustbloc.local:EiBug_0h2oNJj4Vhk7yrC36HvskhngqTJC46VKS-FDM5fA#key-7777",
				Domain:             "issuer.example.com",
				Challenge:          "sample-random-test-value",
				Created:            &createdTime,
				SignatureType:      JSONWebSignature2020,
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SignCredential(&b, bytes.NewBuffer(reqBytes))
		require.NoError(t, err)

		// verify response
		var response SignCredentialResponse
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)
		require.NotEmpty(t, response)

		vc, err := verifiable.ParseCredential(response.VerifiableCredential, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(loader))

		require.NoError(t, err)
		require.NotNil(t, vc)
		require.NotEmpty(t, vc.Proofs)
		require.Len(t, vc.Proofs, 1)
		require.Equal(t, vc.Proofs[0]["challenge"], req.Challenge)
		require.Equal(t, vc.Proofs[0]["domain"], req.Domain)
		require.Equal(t, vc.Proofs[0]["proofPurpose"], "assertionMethod")
		require.Contains(t, vc.Proofs[0]["created"], strconv.Itoa(req.Created.Year()))
		require.Contains(t, vc.Proofs[0]["type"], "JsonWebSignature2020")
	})

	t.Run("test sign credential with proof options - unsupported signature type", func(t *testing.T) {
		req := SignCredentialRequest{
			Credential: []byte(vc),
			DID:        "did:peer:123456789abcdefghi#inbox",
			ProofOptions: &ProofOptions{
				VerificationMethod: "did:peer:123456789abcdefghi#keys-1",
				SignatureType:      "invalid",
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SignCredential(&b, bytes.NewBuffer(reqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature type unsupported invalid")
	})

	t.Run("test sign credential with proof options - signature type empty", func(t *testing.T) {
		req := SignCredentialRequest{
			Credential:   []byte(vc),
			DID:          "did:peer:123456789abcdefghi#inbox",
			ProofOptions: &ProofOptions{Domain: "domain"},
		}

		presReqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SignCredential(&b, bytes.NewBuffer(presReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature type unsupported")
	})

	t.Run("test sign credential - invalid request", func(t *testing.T) {
		var b bytes.Buffer

		err := cmd.SignCredential(&b, bytes.NewBufferString("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	t.Run("test sign credential - validation error", func(t *testing.T) {
		presReq := SignCredentialRequest{
			Credential:   []byte("{}"),
			DID:          "did:peer:123456789abcdefghi#inbox",
			ProofOptions: &ProofOptions{SignatureType: Ed25519Signature2018},
		}
		reqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		var b bytes.Buffer

		err = cmd.SignCredential(&b, bytes.NewBuffer(reqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse vc : build new credential: fill credential types from raw:")
	})

	t.Run("test sign credential - failed to sign credential", func(t *testing.T) {
		presReq := SignCredentialRequest{
			Credential: []byte(vc),
			DID:        "did:error:123",
		}
		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		var b bytes.Buffer

		err = cmd.SignCredential(&b, bytes.NewBuffer(presReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "sign vc - failed to get did doc from store or vdr")
	})
}

func stringToJSONRaw(jsonStr string) json.RawMessage {
	return []byte(jsonStr)
}

func TestCommand_RemoveVCByName(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		// save vc with name
		vcReq := CredentialExt{
			Credential: Credential{VerifiableCredential: vc},
			Name:       sampleCredentialName,
		}
		vcReqBytes, err := json.Marshal(vcReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SaveCredential(&b, bytes.NewBuffer(vcReqBytes))
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{"name":"%s"}`, sampleCredentialName)

		var remRW bytes.Buffer
		cmdErr := cmd.RemoveCredentialByName(&remRW, bytes.NewBufferString(jsoStr))
		require.NoError(t, cmdErr)
	})

	t.Run("invalid request", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		// save vc with name
		vcReq := CredentialExt{
			Credential: Credential{VerifiableCredential: vc},
			Name:       sampleCredentialName,
		}
		vcReqBytes, err := json.Marshal(vcReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SaveCredential(&b, bytes.NewBuffer(vcReqBytes))
		require.NoError(t, err)

		var remRW bytes.Buffer
		cmdErr := cmd.RemoveCredentialByName(&remRW, bytes.NewBufferString("--"))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "request decode")
	})

	t.Run("no name", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		// save vc with name
		vcReq := CredentialExt{
			Credential: Credential{VerifiableCredential: vc},
			Name:       sampleCredentialName,
		}
		vcReqBytes, err := json.Marshal(vcReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SaveCredential(&b, bytes.NewBuffer(vcReqBytes))
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{"name":"%s"}`, "")

		var remRW bytes.Buffer
		cmdErr := cmd.RemoveCredentialByName(&remRW, bytes.NewBufferString(jsoStr))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyCredentialName)
	})

	t.Run("store error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				Store: &mockstore.MockStore{
					ErrGet: fmt.Errorf("get error"),
				},
			},
			DocumentLoaderValue: loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{"name":"%s"}`, sampleCredentialName)

		var b bytes.Buffer
		err = cmd.RemoveCredentialByName(&b, bytes.NewBufferString(jsoStr))
		require.Error(t, err)
		require.Contains(t, err.Error(), "remove vc by name")
	})
}

func TestCommand_RemoveVPByName(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		s := make(map[string]mockstore.DBEntry)
		s["http://example.edu/presentations/1989"] = mockstore.DBEntry{Value: []byte(vc)}

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		// save presentation
		vpReq := PresentationExt{
			Presentation: Presentation{VerifiablePresentation: stringToJSONRaw(udPresentation)},
			Name:         samplePresentationName,
		}
		vpReqBytes, err := json.Marshal(vpReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SavePresentation(&b, bytes.NewBuffer(vpReqBytes))
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{"name":"%s"}`, samplePresentationName)

		var remRW bytes.Buffer
		cmdErr := cmd.RemovePresentationByName(&remRW, bytes.NewBufferString(jsoStr))
		require.NoError(t, cmdErr)
	})

	t.Run("invalid request", func(t *testing.T) {
		s := make(map[string]mockstore.DBEntry)
		s["http://example.edu/presentations/1989"] = mockstore.DBEntry{Value: []byte(vc)}

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		// save presentation
		vpReq := PresentationExt{
			Presentation: Presentation{VerifiablePresentation: stringToJSONRaw(udPresentation)},
			Name:         samplePresentationName,
		}
		vpReqBytes, err := json.Marshal(vpReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SavePresentation(&b, bytes.NewBuffer(vpReqBytes))
		require.NoError(t, err)

		var remRW bytes.Buffer
		cmdErr := cmd.RemovePresentationByName(&remRW, bytes.NewBufferString("--"))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "request decode")
	})

	t.Run("no name", func(t *testing.T) {
		s := make(map[string]mockstore.DBEntry)
		s["http://example.edu/presentations/1989"] = mockstore.DBEntry{Value: []byte(vc)}

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		// save presentation
		vpReq := PresentationExt{
			Presentation: Presentation{VerifiablePresentation: stringToJSONRaw(udPresentation)},
			Name:         samplePresentationName,
		}
		vpReqBytes, err := json.Marshal(vpReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SavePresentation(&b, bytes.NewBuffer(vpReqBytes))
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{"name":"%s"}`, "")

		var remRW bytes.Buffer
		cmdErr := cmd.RemovePresentationByName(&remRW, bytes.NewBufferString(jsoStr))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), errEmptyCredentialName)
	})

	t.Run("store error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				Store: &mockstore.MockStore{
					ErrGet: fmt.Errorf("get error"),
				},
			},
			DocumentLoaderValue: loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{"name":"%s"}`, samplePresentationName)

		var b bytes.Buffer
		err = cmd.RemovePresentationByName(&b, bytes.NewBufferString(jsoStr))
		require.Error(t, err)
		require.Contains(t, err.Error(), "remove vp by name")
	})
}

func TestCommand_DeriveCredential(t *testing.T) {
	r := require.New(t)

	loader, err := ldtestutil.DocumentLoader()
	r.NoError(err)

	vc, err := verifiable.ParseCredential([]byte(vcForDerive), verifiable.WithJSONLDDocumentLoader(loader))
	r.NoError(err)

	r.Len(vc.Proofs, 0)
	didKey := signVCWithBBS(r, vc)
	r.Len(vc.Proofs, 1)

	requestVC, err := vc.MarshalJSON()
	r.NoError(err)
	r.NotEmpty(requestVC)

	mockVDR := &mockvdr.MockVDRegistry{
		ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			if didID == didKey {
				k := key.New()

				d, e := k.Read(didKey)
				if e != nil {
					return nil, e
				}

				return d, nil
			}

			return nil, fmt.Errorf("did not found")
		},
	}

	var frameDoc map[string]interface{}

	r.NoError(json.Unmarshal([]byte(sampleFrame), &frameDoc))

	getRequest := func(r *require.Assertions, rq *DeriveCredentialRequest) io.Reader {
		b, e := json.Marshal(rq)
		r.NoError(e)
		r.NotEmpty(b)

		return bytes.NewBuffer(b)
	}

	t.Run("derive credential success", func(t *testing.T) {
		cmd, cmdErr := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			VDRegistryValue:      mockVDR,
			KMSValue:             &kmsmock.KeyManager{},
			CryptoValue:          &cryptomock.Crypto{},
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, cmdErr)

		nonce := uuid.New().String()

		var b bytes.Buffer

		// call derive credential
		err = cmd.DeriveCredential(&b, getRequest(r, &DeriveCredentialRequest{
			Credential: requestVC,
			Frame:      frameDoc,
			Nonce:      nonce,
		}))

		var response Credential
		err = json.Unmarshal(b.Bytes(), &response)
		r.NoError(err)

		r.NotEmpty(response)
		r.NotEmpty(response.VerifiableCredential)

		// verify VC
		derived, err := verifiable.ParseCredential([]byte(response.VerifiableCredential),
			verifiable.WithPublicKeyFetcher(
				verifiable.NewVDRKeyResolver(mockVDR).PublicKeyFetcher(),
			),
			verifiable.WithJSONLDDocumentLoader(loader),
		)

		// check expected proof
		r.NoError(err)
		r.NotEmpty(derived)
		r.Len(derived.Proofs, 1)
		r.Equal(derived.Proofs[0]["type"], "BbsBlsSignatureProof2020")
		r.NotEmpty(derived.Proofs[0]["nonce"])
		r.EqualValues(derived.Proofs[0]["nonce"], base64.StdEncoding.EncodeToString([]byte(nonce)))
		r.NotEmpty(derived.Proofs[0]["proofValue"])
	})

	t.Run("derive credential request validation", func(t *testing.T) {
		cmd, cmdErr := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			VDRegistryValue:      mockVDR,
			KMSValue:             &kmsmock.KeyManager{},
			CryptoValue:          &cryptomock.Crypto{},
			DocumentLoaderValue:  loader,
		})
		require.NotNil(t, cmd)
		require.NoError(t, cmdErr)

		reqBytes, err := json.Marshal([]map[string]interface{}{})
		r.NoError(err)
		r.NotEmpty(reqBytes)

		var b bytes.Buffer

		// call derive credential with invalid request
		cErr := cmd.DeriveCredential(&b, bytes.NewBuffer(reqBytes))
		r.Error(cErr)
		r.Equal(InvalidRequestErrorCode, cErr.Code())
		r.Equal(command.ValidationError, cErr.Type())
		r.Contains(cErr.Error(), "request decode")

		// call derive credential with empty request
		cErr = cmd.DeriveCredential(&b, getRequest(r, &DeriveCredentialRequest{}))
		r.Error(cErr)
		r.Equal(InvalidRequestErrorCode, cErr.Code())
		r.Equal(command.ValidationError, cErr.Type())
		r.Contains(cErr.Error(), errEmptyCredential)

		// call derive credential with missing frame
		cErr = cmd.DeriveCredential(&b, getRequest(r, &DeriveCredentialRequest{
			Credential: json.RawMessage(requestVC),
		}))
		r.Error(cErr)
		r.Equal(InvalidRequestErrorCode, cErr.Code())
		r.Equal(command.ValidationError, cErr.Type())
		r.Contains(cErr.Error(), errEmptyFrame)

		// call derive credential with invalid credential
		cErr = cmd.DeriveCredential(&b, getRequest(r, &DeriveCredentialRequest{
			Credential: json.RawMessage(vcWithDIDNotAvailble),
			Frame:      frameDoc,
		}))
		r.Error(cErr)
		r.Equal(DeriveCredentialErrorCode, cErr.Code())
		r.Equal(command.ValidationError, cErr.Type())
		r.Contains(cErr.Error(), "failed to parse request vc")

		// call derive credential with invalid credential but skip VC verify
		cErr = cmd.DeriveCredential(&b, getRequest(r, &DeriveCredentialRequest{
			Credential: json.RawMessage(vcWithDIDNotAvailble),
			Frame:      frameDoc,
			SkipVerify: true,
		}))
		r.Error(cErr)
		r.Equal(DeriveCredentialErrorCode, cErr.Code())
		r.Equal(command.ExecuteError, cErr.Type())
		r.Contains(cErr.Error(), "failed to derive credential")
	})
}

// signVCWithBBS signs VC with bbs and returns did used for signing.
func signVCWithBBS(r *require.Assertions, vc *verifiable.Credential) string {
	pubKey, privKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
	r.NoError(err)
	r.NotEmpty(privKey)

	pubKeyBytes, err := pubKey.Marshal()
	r.NoError(err)

	didKey, keyID := fingerprint.CreateDIDKeyByCode(fingerprint.BLS12381g2PubKeyMultiCodec, pubKeyBytes)

	bbsSigner, err := newBBSSigner(privKey)
	r.NoError(err)

	sigSuite := bbsblssignature2020.New(
		suite.WithSigner(bbsSigner),
		suite.WithVerifier(bbsblssignature2020.NewG2PublicKeyVerifier()))

	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: verifiable.SignatureProofValue,
		Suite:                   sigSuite,
		VerificationMethod:      keyID,
	}

	loader, err := ldtestutil.DocumentLoader()
	r.NoError(err)

	err = vc.AddLinkedDataProof(ldpContext, jsonldsig.WithDocumentLoader(loader))
	r.NoError(err)

	vcSignedBytes, err := json.Marshal(vc)
	r.NoError(err)
	r.NotEmpty(vcSignedBytes)

	vcVerified, err := verifiable.ParseCredential(vcSignedBytes,
		verifiable.WithEmbeddedSignatureSuites(sigSuite),
		verifiable.WithPublicKeyFetcher(verifiable.SingleKey(pubKeyBytes, "Bls12381G2Key2020")),
		verifiable.WithJSONLDDocumentLoader(loader),
	)
	r.NoError(err)
	r.NotNil(vcVerified)

	return didKey
}

type bbsSigner struct {
	privKeyBytes []byte
}

func newBBSSigner(privKey *bbs12381g2pub.PrivateKey) (*bbsSigner, error) {
	privKeyBytes, err := privKey.Marshal()
	if err != nil {
		return nil, err
	}

	return &bbsSigner{privKeyBytes: privKeyBytes}, nil
}

func (s *bbsSigner) Sign(data []byte) ([]byte, error) {
	msgs := s.textToLines(string(data))

	return bbs12381g2pub.New().Sign(msgs, s.privKeyBytes)
}

func (s *bbsSigner) Alg() string {
	return ""
}

func (s *bbsSigner) textToLines(txt string) [][]byte {
	lines := strings.Split(txt, "\n")
	linesBytes := make([][]byte, 0, len(lines))

	for i := range lines {
		if strings.TrimSpace(lines[i]) != "" {
			linesBytes = append(linesBytes, []byte(lines[i]))
		}
	}

	return linesBytes
}

func createTestDocumentLoader(t *testing.T) *ld.DocumentLoader {
	t.Helper()

	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	return loader
}

func TestBuildKIDOption(t *testing.T) {
	opts := &ProofOptions{
		VerificationMethod: "#key-1",
	}

	t.Run("test buildKIDOption() - get public key bytes from Ed25519", func(t *testing.T) {
		vms := []did.VerificationMethod{
			{
				ID:    "#key-1",
				Type:  "Ed25519VerificationKey2018",
				Value: base58.Decode("59JheJuqWVo6Z6fg2sDaHYNNyFHv2eWiU92iM5tSQWxf"),
			},
		}

		kid := "FqTYWwv_lRAdZcROZiNLYDey4bx4vHa-5dqExUE5PRE"

		err := buildKIDOption(opts, vms)
		require.NoError(t, err)
		require.Equal(t, kid, opts.KID)
	})

	tests := []struct {
		name        string
		jwkJSON     string
		expectedKID string
	}{
		{
			name: "get public key bytes JWK with EC P-256 Key",
			jwkJSON: `{
							"kty": "EC",
							"use": "enc",
							"crv": "P-256",
							"kid": "sample@sample.id",
							"x": "JR7nhI47w7bxrNkp7Xt1nbmozNn-RB2Q-PWi7KHT8J0",
							"y": "iXmKtH0caOgB1vV0CQwinwK999qdDvrssKhdbiAz9OI",
							"alg": "ES256"
						}`,
			expectedKID: "mH-_W9uC7Kyl_7WerlU14mwSWwoUAKOnfDfl-c2UZc0",
		},
		{
			name: "get public key bytes EC P-384 JWK",
			jwkJSON: `{
							"kty": "EC",
							"use": "enc",
							"crv": "P-384",
							"kid": "sample@sample.id",
							"x": "GGFw14WnABx5S__MLwjy7WPgmPzCNbygbJikSqwx1nQ7APAiIyLeiAeZnAFQSr8C",
							"y": "Bjev4lkaRbd4Ery0vnO8Ox4QgIDGbuflmFq0HhL-QHIe3KhqxrqZqbQYGlDNudEv",
							"alg": "ES384"
						}`,
			expectedKID: "ifJcCtk6M3ydFqfN7EB57U3HnWy2jazWcA9mAMD-WRw",
		},
		{
			name: "get public key bytes EC P-521 JWK",
			jwkJSON: `{
							"kty": "EC",
							"use": "enc",
							"crv": "P-521",
							"kid": "sample@sample.id",
							"x": "AZi-AxJkB09qw8dBnNrz53xM-wER0Y5IYXSEWSTtzI5Sdv_5XijQn9z-vGz1pMdww-C75GdpAzp2ghejZJSxbAd6",
							"y": "AZzRvW8NBytGNbF3dyNOMHB0DHCOzGp8oYBv_ZCyJbQUUnq-TYX7j8-PlKe9Ce5acxZzrcUKVtJ4I8JgI5x9oXIW",
							"alg": "ES521"
						}`,
			expectedKID: "7icoqReWFlpF16dzZD3rBgK1cJ265WzfF9sJJXqOe0M",
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run("test buildKIDOption() - "+tc.name, func(t *testing.T) {
			jwkKey := &jwk.JWK{}

			err := json.Unmarshal([]byte(tc.jwkJSON), jwkKey)
			require.NoError(t, err)

			vm, err := did.NewVerificationMethodFromJWK("#key-1", "JsonWebKey2020", "", jwkKey)
			require.NoError(t, err)

			vms := []did.VerificationMethod{*vm}
			err = buildKIDOption(opts, vms)
			require.NoError(t, err)
			require.EqualValuesf(t, tc.expectedKID, opts.KID, tc.name)
		})
	}
}

func TestNewKMSSignerAlg(t *testing.T) {
	t.Run("test signer Alg()", func(t *testing.T) {
		tests := []struct {
			name        string
			kmsKT       kmsapi.KeyType
			expectedAlg string
		}{
			{
				name:        "test ECDSA alg from P256 key type in DER format",
				kmsKT:       kmsapi.ECDSAP256DER,
				expectedAlg: p256Alg,
			},
			{
				name:        "test ECDSA alg from P256 key type in IEEE format",
				kmsKT:       kmsapi.ECDSAP256IEEEP1363,
				expectedAlg: p256Alg,
			},
			{
				name:        "test ECDSA alg from P384 key type in DER format",
				kmsKT:       kmsapi.ECDSAP384DER,
				expectedAlg: p384Alg,
			},
			{
				name:        "test ECDSA alg from P384 key type in IEEE format",
				kmsKT:       kmsapi.ECDSAP384IEEEP1363,
				expectedAlg: p384Alg,
			},
			{
				name:        "test ECDSA alg from P521 key type in DER format",
				kmsKT:       kmsapi.ECDSAP521DER,
				expectedAlg: p521Alg,
			},
			{
				name:        "test ECDSA alg from P521 key type in IEEE format",
				kmsKT:       kmsapi.ECDSAP521IEEEP1363,
				expectedAlg: p521Alg,
			},
			{
				name:        "test EdDSA alg from ed25519 key type",
				kmsKT:       kmsapi.ED25519,
				expectedAlg: edAlg,
			},
			{
				name: "test empty alg from empty key type",
			},
		}

		for _, tt := range tests {
			tc := tt

			t.Run(tc.name, func(t *testing.T) {
				signer, err := newKMSSigner(&kmsmock.KeyManager{ExportPubKeyTypeValue: tc.kmsKT}, &cryptomock.Crypto{}, "123")
				require.NoError(t, err)

				alg := signer.Alg()
				require.Equal(t, tc.expectedAlg, alg)
			})
		}
	})
}
