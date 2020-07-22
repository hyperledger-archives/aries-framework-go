/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	kmsmock "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	verifiablestore "github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
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
  "publicKey": [
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

//nolint:lll
const invalidDoc = `{
  "@context": ["https://w3id.org/did/v1","https://w3id.org/did/v2"],
  "id": "did:peer:21tDAKCERh95uGgKbJNHYp",
  "publicKey": [
  ]
}`

//nolint:lll
const jwsDIDDoc = `{
    "@context":["https://w3id.org/did/v1"], 
	"id": "did:trustbloc:testnet.trustbloc.local:EiBug_0h2oNJj4Vhk7yrC36HvskhngqTJC46VKS-FDM5fA",
	"authentication" : [ "did:trustbloc:testnet.trustbloc.local:EiBug_0h2oNJj4Vhk7yrC36HvskhngqTJC46VKS-FDM5fA#key-7777" ],
	"assertionMethod" : [ "did:trustbloc:testnet.trustbloc.local:EiBug_0h2oNJj4Vhk7yrC36HvskhngqTJC46VKS-FDM5fA#key-7777" ],
    "publicKey": [{
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
  "publicKey" : [ {
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
  "publicKey": [
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
  "publicKey": [
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

const invalidDID = "did:error:123"
const jwsDID = "did:trustbloc:testnet.trustbloc.local:EiBug_0h2oNJj4Vhk7yrC36HvskhngqTJC46VKS-FDM5fA"

func TestNew(t *testing.T) {
	t.Run("test new command - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		handlers := cmd.GetHandlers()
		require.Equal(t, 13, len(handlers))
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
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
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
	t.Run("test save vc - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
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
	t.Run("test get vc - success", func(t *testing.T) {
		s := make(map[string][]byte)
		s["http://example.edu/credentials/1989"] = []byte(vc)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
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
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{}`)

		var b bytes.Buffer
		err = cmd.GetCredential(&b, bytes.NewBufferString(jsoStr))
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
	t.Run("test get vc by name - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
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
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{}`)

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
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
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
	s := make(map[string][]byte)
	cmd, cmdErr := New(&mockprovider.Provider{
		StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
		VDRIRegistryValue: &mockvdri.MockVDRIRegistry{
			ResolveFunc: func(didID string, opts ...vdri.ResolveOpts) (*did.Doc, error) {
				if didID == invalidDID {
					return nil, errors.New("invalid")
				}

				if didID == jwsDID {
					jwsDoc, err := did.ParseDocument([]byte(jwsDIDDoc))
					if err != nil {
						return nil, errors.New("unmarshal failed ")
					}
					return jwsDoc, nil
				}

				didDoc, err := did.ParseDocument([]byte(doc))
				if err != nil {
					return nil, errors.New("unmarshal failed ")
				}
				return didDoc, nil
			},
		},
		KMSValue:    &kmsmock.KeyManager{},
		CryptoValue: &cryptomock.Crypto{},
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
			verifiable.WithPresDisabledProofCheck())

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
			verifiable.WithPresDisabledProofCheck())

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Equal(t, presReq.DID, vp.Holder)
		require.NotEmpty(t, vp.Proofs)
		require.Len(t, vp.Proofs, 1)
		require.Equal(t, vp.Proofs[0]["challenge"], presReq.Challenge)
		require.Equal(t, vp.Proofs[0]["domain"], presReq.Domain)
		require.Equal(t, vp.Proofs[0]["proofPurpose"], "authentication")
		require.Contains(t, vp.Proofs[0]["created"], strconv.Itoa(presReq.Created.Year()))
		require.Equal(t, vp.Proofs[0]["verificationMethod"],
			"did:peer:123456789abcdefghi#keys-1")
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
			verifiable.WithPresDisabledProofCheck())

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
			verifiable.WithPresDisabledProofCheck())

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
			verifiable.WithPresDisabledProofCheck())

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
			ProofOptions:          &ProofOptions{SignatureType: Ed25519Signature2018}}
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
			DID:                   "did:error:123"}
		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		var b bytes.Buffer

		err = cmd.GeneratePresentation(&b, bytes.NewBuffer(presReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "generate vp - failed to get did doc from store or vdri")
	})
}

func TestGeneratePresentationByID(t *testing.T) {
	s := make(map[string][]byte)
	cmd, cmdErr := New(&mockprovider.Provider{
		StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
		VDRIRegistryValue: &mockvdri.MockVDRIRegistry{
			ResolveFunc: func(didID string, opts ...vdri.ResolveOpts) (didDoc *did.Doc, e error) {
				if didID == invalidDID {
					return nil, errors.New("invalid")
				}
				didDoc, err := did.ParseDocument([]byte(doc))
				if err != nil {
					return nil, errors.New("unmarshal failed ")
				}
				return didDoc, nil
			},
		},
		KMSValue:    &kmsmock.KeyManager{},
		CryptoValue: &cryptomock.Crypto{},
	})
	require.NotNil(t, cmd)
	require.NoError(t, cmdErr)

	t.Run("test generate presentation - success", func(t *testing.T) {
		s["http://example.edu/credentials/1989"] = []byte(vc)
		s["did:peer:21tDAKCERh95uGgKbJNHYp"] = []byte(doc)

		presIDArgs := PresentationRequestByID{
			ID:            "http://example.edu/credentials/1989",
			DID:           "did:peer:21tDAKCERh95uGgKbJNHYp",
			SignatureType: Ed25519Signature2018}
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
		s["http://example.edu/credentials/1989"] = []byte(vc)
		s["test"] = []byte(doc)

		presIDArgs := PresentationRequestByID{ID: "http://example.edu/credentials/1989", DID: "notFoundDID"}
		presReqBytes, e := json.Marshal(presIDArgs)
		require.NoError(t, e)

		var getRW bytes.Buffer
		cmdErr := cmd.GeneratePresentationByID(&getRW, bytes.NewBuffer(presReqBytes))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "failed to get did doc from store")
	})

	t.Run("test generate presentation - invalid request", func(t *testing.T) {
		var b bytes.Buffer
		err := cmd.GeneratePresentationByID(&b, bytes.NewBufferString("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	t.Run("test generate presentation - no id in the request", func(t *testing.T) {
		jsoStr := fmt.Sprintf(`{}`)

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
	s := make(map[string][]byte)
	cmd, cmdErr := New(&mockprovider.Provider{
		StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
		VDRIRegistryValue: &mockvdri.MockVDRIRegistry{
			ResolveFunc: func(didID string, opts ...vdri.ResolveOpts) (didDoc *did.Doc, e error) {
				if didID == invalidDID {
					return nil, errors.New("invalid")
				}
				didDoc, err := did.ParseDocument([]byte(doc))
				if err != nil {
					return nil, errors.New("unmarshal failed ")
				}
				return didDoc, nil
			},
		},
		KMSValue: &kmsmock.KeyManager{},
	})
	require.NotNil(t, cmd)
	require.NoError(t, cmdErr)

	t.Run("test generate presentation helper- error", func(t *testing.T) {
		v := &verifiable.Credential{}
		err := json.Unmarshal([]byte(vc), v)
		require.NoError(t, err)

		credList := make([]interface{}, 1)
		credList[0] = v

		var b bytes.Buffer
		err = cmd.generatePresentation(&b, credList, nil, "did:example", &ProofOptions{VerificationMethod: "pk"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "prepare vp: failed to sign vp: wrong id [pk] to resolve")
	})

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
			VDRIRegistryValue: &mockvdri.MockVDRIRegistry{
				ResolveFunc: func(didID string, opts ...vdri.ResolveOpts) (didDoc *did.Doc, e error) {
					if didID == invalidDID {
						return nil, errors.New("invalid")
					}
					didDoc, err := did.ParseDocument([]byte(doc))
					if err != nil {
						return nil, errors.New("unmarshal failed ")
					}
					return didDoc, nil
				},
			},
			KMSValue:    &kmsmock.KeyManager{},
			CryptoValue: &cryptomock.Crypto{SignErr: errors.New("invalid signer")},
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
	t.Run("test save vp - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
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
	t.Run("test get vp - success", func(t *testing.T) {
		s := make(map[string][]byte)
		s["http://example.edu/presentations/1989"] = []byte(vc)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
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

		jsoStr := fmt.Sprintf(`{"id":"http://example.edu/presentations/1989"}`)

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
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{}`)

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
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{"id":"http://example.edu/presentations/1989"}`)

		var b bytes.Buffer
		err = cmd.GetPresentation(&b, bytes.NewBufferString(jsoStr))
		require.Error(t, err)
		require.Contains(t, err.Error(), "get vp")
	})
}

func TestGetPresentations(t *testing.T) {
	t.Run("test get credentials", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
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
	s := make(map[string][]byte)
	cmd, cmdErr := New(&mockprovider.Provider{
		StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
		VDRIRegistryValue: &mockvdri.MockVDRIRegistry{
			ResolveFunc: func(didID string, opts ...vdri.ResolveOpts) (*did.Doc, error) {
				if didID == invalidDID {
					return nil, errors.New("invalid")
				}

				if didID == jwsDID {
					jwsDoc, err := did.ParseDocument([]byte(jwsDIDDoc))
					if err != nil {
						return nil, errors.New("unmarshal failed ")
					}
					return jwsDoc, nil
				}

				didDoc, err := did.ParseDocument([]byte(doc))
				if err != nil {
					return nil, errors.New("unmarshal failed ")
				}
				return didDoc, nil
			},
		},
		KMSValue:    &kmsmock.KeyManager{},
		CryptoValue: &cryptomock.Crypto{},
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

		vc, err := verifiable.ParseCredential(response.VerifiableCredential, verifiable.WithDisabledProofCheck())

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

		vp, err := verifiable.ParseCredential(response.VerifiableCredential, verifiable.WithDisabledProofCheck())

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.NotEmpty(t, vp.Proofs)
		require.Len(t, vp.Proofs, 1)
		require.Equal(t, vp.Proofs[0]["challenge"], req.Challenge)
		require.Equal(t, vp.Proofs[0]["domain"], req.Domain)
		require.Equal(t, vp.Proofs[0]["proofPurpose"], "assertionMethod")
		require.Contains(t, vp.Proofs[0]["created"], strconv.Itoa(req.Created.Year()))
		require.Equal(t, vp.Proofs[0]["verificationMethod"],
			"did:peer:123456789abcdefghi#keys-1")
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

		vc, err := verifiable.ParseCredential(response.VerifiableCredential, verifiable.WithDisabledProofCheck())

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

		vc, err := verifiable.ParseCredential(response.VerifiableCredential, verifiable.WithDisabledProofCheck())

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
			ProofOptions: &ProofOptions{SignatureType: Ed25519Signature2018}}
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
			DID:        "did:error:123"}
		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		var b bytes.Buffer

		err = cmd.SignCredential(&b, bytes.NewBuffer(presReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "generate vp - failed to get did doc from store or vdri")
	})
}

func stringToJSONRaw(jsonStr string) json.RawMessage {
	return []byte(jsonStr)
}

func TestCommand_RemoveVCByName(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
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
	t.Run("success", func(t *testing.T) {
		s := make(map[string][]byte)
		s["http://example.edu/presentations/1989"] = []byte(vc)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
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
		s := make(map[string][]byte)
		s["http://example.edu/presentations/1989"] = []byte(vc)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
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
		s := make(map[string][]byte)
		s["http://example.edu/presentations/1989"] = []byte(vc)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
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
