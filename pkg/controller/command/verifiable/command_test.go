/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	kmsmock "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
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
      "https://www.w3.org/2018/credentials/v1"
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
      "https://www.w3.org/2018/credentials/v1"
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
    "@context":
        ["https://w3id.org/did/v1"], "id":
        "did:trustbloc:testnet.trustbloc.local:EiBug_0h2oNJj4Vhk7yrC36HvskhngqTJC46VKS-FDM5fA", 
    "publicKey": [{
            "controller": "did:trustbloc:testnet.trustbloc.local:EiBug_0h2oNJj4Vhk7yrC36HvskhngqTJC46VKS-FDM5fA",
            "id": "did:trustbloc:testnet.trustbloc.local:EiBug_0h2oNJj4Vhk7yrC36HvskhngqTJC46VKS-FDM5fA#key-7777",
            "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "tp-lwePd7QnwWaxCLZ76-fPj2mjA-3z_ivCfBmZoDNA"},
            "type": "JwsVerificationKey2020"
        }]
}
`

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
		require.Equal(t, 10, len(handlers))
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
		require.Len(t, response.Result[0].Context, 1)
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
		require.Contains(t, err.Error(), "#key-1 is not found for DID did:trustbloc:testnet.trustbloc.local")

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
				VerificationMethod: "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ#signing-key",
				Domain:             "issuer.example.com",
				Challenge:          "sample-random-test-value",
				ProofPurpose:       "authentication",
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

		vp, err := verifiable.NewPresentation([]byte(response.VerifiablePresentation))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.NotEmpty(t, vp.Proofs)
		require.Len(t, vp.Proofs, 1)
		require.Equal(t, vp.Proofs[0]["challenge"], presReq.Challenge)
		require.Equal(t, vp.Proofs[0]["domain"], presReq.Domain)
		require.Equal(t, vp.Proofs[0]["proofPurpose"], presReq.ProofPurpose)
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
				ProofPurpose:  "authentication",
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

		vp, err := verifiable.NewPresentation([]byte(response.VerifiablePresentation))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.NotEmpty(t, vp.Proofs)
		require.Len(t, vp.Proofs, 1)
		require.Equal(t, vp.Proofs[0]["challenge"], presReq.Challenge)
		require.Equal(t, vp.Proofs[0]["domain"], presReq.Domain)
		require.Equal(t, vp.Proofs[0]["proofPurpose"], presReq.ProofPurpose)
		require.Contains(t, vp.Proofs[0]["created"], strconv.Itoa(presReq.Created.Year()))
		require.Equal(t, vp.Proofs[0]["verificationMethod"],
			"did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ#signing-key")
	})

	t.Run("test generate presentation with proof options - success (p256 jsonwebsignature)", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		encodedPrivateKey, err := x509.MarshalECPrivateKey(privateKey)
		require.NoError(t, err)

		credList := []json.RawMessage{[]byte(vc), []byte(vc)}

		createdTime := time.Now().AddDate(-1, 0, 0)
		presReq := PresentationRequest{
			VerifiableCredentials: credList,
			DID:                   "did:peer:123456789abcdefghi#inbox",
			ProofOptions: &ProofOptions{
				Domain:        "issuer.example.com",
				Challenge:     "sample-random-test-value",
				ProofPurpose:  "authentication",
				Created:       &createdTime,
				DIDKeyID:      "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ#signing-key",
				PrivateKey:    base58.Encode(encodedPrivateKey),
				SignatureType: JSONWebSignature2020,
				KeyType:       P256KeyType,
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

		vp, err := verifiable.NewPresentation([]byte(response.VerifiablePresentation))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.NotEmpty(t, vp.Proofs)
		require.Len(t, vp.Proofs, 1)
		require.Equal(t, vp.Proofs[0]["challenge"], presReq.Challenge)
		require.Equal(t, vp.Proofs[0]["domain"], presReq.Domain)
		require.Equal(t, vp.Proofs[0]["proofPurpose"], presReq.ProofPurpose)
		require.Contains(t, vp.Proofs[0]["created"], strconv.Itoa(presReq.Created.Year()))
		require.Contains(t, vp.Proofs[0]["type"], "JsonWebSignature2020")
	})

	t.Run("test generate presentation with proof options - success (ed25519 jsonwebsignature)", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		credList := []json.RawMessage{[]byte(vc), []byte(vc)}

		createdTime := time.Now().AddDate(-1, 0, 0)
		presReq := PresentationRequest{
			VerifiableCredentials: credList,
			DID:                   "did:peer:123456789abcdefghi#inbox",
			ProofOptions: &ProofOptions{
				VerificationMethod: "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ#signing-key",
				Domain:             "issuer.example.com",
				Challenge:          "sample-random-test-value",
				ProofPurpose:       "authentication",
				Created:            &createdTime,
				PrivateKey:         base58.Encode(privateKey),
				SignatureType:      JSONWebSignature2020,
				KeyType:            Ed25519KeyType,
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

		vp, err := verifiable.NewPresentation([]byte(response.VerifiablePresentation))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.NotEmpty(t, vp.Proofs)
		require.Len(t, vp.Proofs, 1)
		require.Equal(t, vp.Proofs[0]["challenge"], presReq.Challenge)
		require.Equal(t, vp.Proofs[0]["domain"], presReq.Domain)
		require.Equal(t, vp.Proofs[0]["proofPurpose"], presReq.ProofPurpose)
		require.Contains(t, vp.Proofs[0]["created"], strconv.Itoa(presReq.Created.Year()))
		require.Contains(t, vp.Proofs[0]["type"], "JsonWebSignature2020")
	})

	t.Run("test generate presentation with proof options - invalid key type", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		credList := []json.RawMessage{[]byte(vc), []byte(vc)}

		presReq := PresentationRequest{
			VerifiableCredentials: credList,
			DID:                   "did:peer:123456789abcdefghi#inbox",
			ProofOptions: &ProofOptions{
				PrivateKey:    base58.Encode(privateKey),
				KeyType:       "invalid-key-type",
				SignatureType: JSONWebSignature2020,
			},
		}

		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.GeneratePresentation(&b, bytes.NewBuffer(presReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid key type : invalid-key-type")
	})

	t.Run("test generate presentation with proof options - unsupported signature type", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		credList := []json.RawMessage{[]byte(vc), []byte(vc)}

		presReq := PresentationRequest{
			VerifiableCredentials: credList,
			DID:                   "did:peer:123456789abcdefghi#inbox",
			ProofOptions: &ProofOptions{
				PrivateKey:    base58.Encode(privateKey),
				KeyType:       Ed25519Signature2018,
				SignatureType: "invalid",
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
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		credList := []json.RawMessage{[]byte(vc), []byte(vc)}

		presReq := PresentationRequest{
			VerifiableCredentials: credList,
			DID:                   "did:peer:123456789abcdefghi#inbox",
			ProofOptions: &ProofOptions{
				PrivateKey: base58.Encode(privateKey),
			},
		}

		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.GeneratePresentation(&b, bytes.NewBuffer(presReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature type empty")
	})

	t.Run("test generate verifiable presentation with proof options & presentation - success", func(t *testing.T) {
		pRaw := json.RawMessage([]byte(`{"@context": "https://www.w3.org/2018/credentials/v1",
		"type": "VerifiablePresentation","holder": "did:web:vc.example.world"}`))

		createdTime := time.Now().AddDate(-1, 0, 0)
		presReq := PresentationRequest{
			Presentation: pRaw,
			DID:          "did:peer:123456789abcdefghi#inbox",
			ProofOptions: &ProofOptions{
				VerificationMethod: "did:sample:EiAiSE10ugVUHXsOp4pm86oN6LnjuCdrkt3s12rcVFkilQ#signing-key",
				Domain:             "issuer.example.com",
				Challenge:          "sample-random-test-value",
				ProofPurpose:       "authentication",
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

		vp, err := verifiable.NewPresentation([]byte(response.VerifiablePresentation))

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.Empty(t, vp.Credentials())
		require.NotEmpty(t, vp.Proofs)
		require.Equal(t, vp.Holder, "did:web:vc.example.world")
		require.Len(t, vp.Proofs, 1)
		require.Equal(t, vp.Proofs[0]["challenge"], presReq.Challenge)
		require.Equal(t, vp.Proofs[0]["domain"], presReq.Domain)
		require.Equal(t, vp.Proofs[0]["proofPurpose"], presReq.ProofPurpose)
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
		err = cmd.generatePresentation(&b, credList, nil, &ProofOptions{VerificationMethod: "pk"})
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
			VerifiableCredentials: credList,
		}

		vc, p, _, err := cmd.parsePresentationRequest(req, nil)
		require.Error(t, err)
		require.Nil(t, vc)
		require.Nil(t, p)
		require.Contains(t, err.Error(), "no valid credentials/presentation found")
	})

	t.Run("test parse presentation- public key not found in DID Document", func(t *testing.T) {
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

func stringToJSONRaw(jsonStr string) json.RawMessage {
	return json.RawMessage([]byte(jsonStr))
}
