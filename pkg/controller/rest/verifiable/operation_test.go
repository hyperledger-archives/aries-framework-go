/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	verifiableapi "github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	kmsmock "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
)

const sampleCredentialName = "sampleVCName"
const samplePresentationName = "sampleVPName"
const sampleVCID = "http://example.edu/credentials/1989"
const sampleVPID = "http://example.edu/presentations/1989"
const invalidDID = "did:error:1234"

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

//nolint:lll
const doc = `{
  "@context": ["https://w3id.org/did/v1","https://w3id.org/did/v2"],
  "id": "did:peer:21tDAKCERh95uGgKbJNHYp",
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

func TestNew(t *testing.T) {
	t.Run("test new command - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)
		require.Equal(t, 13, len(cmd.GetRESTHandlers()))
	})

	t.Run("test new command - error", func(t *testing.T) {
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
	t.Run("test validate vc - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		vcReq := verifiable.Credential{VerifiableCredential: vc}
		jsonStr, err := json.Marshal(vcReq)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, ValidateCredentialPath, http.MethodPost)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)

		response := emptyRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.Empty(t, response)
	})

	t.Run("test validate vc - error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var jsonStr = []byte(`{
		}`)

		handler := lookupHandler(t, cmd, ValidateCredentialPath, http.MethodPost)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, verifiable.ValidateCredentialErrorCode, "validate vc : decode new credential", buf.Bytes())
	})
}

func TestSaveVC(t *testing.T) {
	t.Run("test save vc - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		vcReq := verifiable.CredentialExt{
			Credential: verifiable.Credential{VerifiableCredential: vc},
			Name:       sampleCredentialName,
		}
		jsonStr, err := json.Marshal(vcReq)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, SaveCredentialPath, http.MethodPost)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)

		response := emptyRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.Empty(t, response)
	})

	t.Run("test save vc - error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var jsonStr = []byte(`{
			"name" : "sample"
		}`)

		handler := lookupHandler(t, cmd, SaveCredentialPath, http.MethodPost)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, verifiable.SaveCredentialErrorCode, "parse vc : unmarshal new credential", buf.Bytes())
	})
}

func TestGetVC(t *testing.T) {
	t.Run("test get vc - success", func(t *testing.T) {
		s := make(map[string][]byte)
		s["http://example.edu/credentials/1989"] = []byte(vc)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)
		fmt.Println(base64.StdEncoding.EncodeToString([]byte("http://example.edu/credentials/1989")))

		handler := lookupHandler(t, cmd, GetCredentialPath, http.MethodGet)
		buf, err := getSuccessResponseFromHandler(handler, nil, fmt.Sprintf(`%s/%s`,
			verifiableCredentialPath, base64.StdEncoding.EncodeToString([]byte("http://example.edu/credentials/1989"))))
		require.NoError(t, err)

		response := credentialRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
	})

	t.Run("test get vc - error", func(t *testing.T) {
		s := make(map[string][]byte)
		s["http://example.edu/credentials/1989"] = []byte(vc)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handler := lookupHandler(t, cmd, GetCredentialPath, http.MethodGet)
		buf, code, err := sendRequestToHandler(handler, nil, fmt.Sprintf(`%s/%s`, verifiableCredentialPath, "abc"))
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, verifiable.InvalidRequestErrorCode, "illegal base64 data", buf.Bytes())
	})
}

func TestGetCredentialByName(t *testing.T) {
	t.Run("test get vc by name - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		vcReq := verifiable.CredentialExt{
			Credential: verifiable.Credential{VerifiableCredential: vc},
			Name:       sampleCredentialName,
		}
		jsonStr, err := json.Marshal(vcReq)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, SaveCredentialPath, http.MethodPost)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		handler = lookupHandler(t, cmd, GetCredentialByNamePath, http.MethodGet)
		buf, err = getSuccessResponseFromHandler(handler, nil, fmt.Sprintf(`%s/name/%s`,
			verifiableCredentialPath, sampleCredentialName))
		require.NoError(t, err)

		response := credentialRecord{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.Equal(t, sampleCredentialName, response.Name)
		require.Equal(t, sampleVCID, response.ID)
	})

	t.Run("test get vc by name - error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handler := lookupHandler(t, cmd, GetCredentialByNamePath, http.MethodGet)
		buf, code, err := sendRequestToHandler(handler, nil, fmt.Sprintf(`%s/name/%s`,
			verifiableCredentialPath, sampleCredentialName))
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, verifiable.GetCredentialByNameErrorCode, "get vc by name", buf.Bytes())
	})
}

func TestGetCredentials(t *testing.T) {
	t.Run("test get credentials", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		vcReq := verifiable.CredentialExt{
			Credential: verifiable.Credential{VerifiableCredential: vc},
			Name:       sampleCredentialName,
		}
		jsonStr, err := json.Marshal(vcReq)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, SaveCredentialPath, http.MethodPost)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		handler = lookupHandler(t, cmd, GetCredentialsPath, http.MethodGet)
		buf, err = getSuccessResponseFromHandler(handler, nil, GetCredentialsPath)
		require.NoError(t, err)

		var response credentialRecordResult
		err = json.Unmarshal(buf.Bytes(), &response)
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
		vcs := []json.RawMessage{[]byte(vc)}

		presReq := verifiable.PresentationRequest{
			VerifiableCredentials: vcs,
			DID:                   "did:peer:21tDAKCERh95uGgKbJNHYp",
			ProofOptions: &verifiable.ProofOptions{
				SignatureType: verifiable.Ed25519Signature2018,
			},
		}

		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, GeneratePresentationPath, http.MethodPost)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(presReqBytes), handler.Path())
		require.NoError(t, err, err)

		response := presentationRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.VerifiablePresentation)
	})

	t.Run("test generate presentation skip verify - success", func(t *testing.T) {
		vcs := []json.RawMessage{[]byte(vcWithDIDNotAvailble)}

		presReq := verifiable.PresentationRequest{
			VerifiableCredentials: vcs,
			DID:                   "did:peer:21tDAKCERh95uGgKbJNHYp",
			ProofOptions: &verifiable.ProofOptions{
				SignatureType: verifiable.Ed25519Signature2018,
			},
		}
		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, GeneratePresentationPath, http.MethodPost)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(presReqBytes), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, verifiable.GeneratePresentationErrorCode,
			"#key-1 is not found for DID did:trustbloc:testnet.trustbloc.local:", buf.Bytes())

		// now try by skipping verification
		presReq.SkipVerify = true
		presReqBytes, err = json.Marshal(presReq)
		require.NoError(t, err)

		buf, err = getSuccessResponseFromHandler(handler, bytes.NewBuffer(presReqBytes), handler.Path())
		require.NoError(t, err)

		response := presentationRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.VerifiablePresentation)
	})

	t.Run("test generate presentation with options - success", func(t *testing.T) {
		vcs := []json.RawMessage{[]byte(vc)}

		createdTime := time.Now().AddDate(-1, 0, 0)
		presReq := verifiable.PresentationRequest{
			VerifiableCredentials: vcs,
			DID:                   "did:peer:21tDAKCERh95uGgKbJNHYp",
			ProofOptions: &verifiable.ProofOptions{
				VerificationMethod: "did:peer:123456789abcdefghi#keys-1",
				Domain:             "issuer.example.com",
				Challenge:          "sample-random-test-value",
				Created:            &createdTime,
				SignatureType:      verifiable.Ed25519Signature2018,
			},
		}
		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, GeneratePresentationPath, http.MethodPost)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(presReqBytes), handler.Path())
		require.NoError(t, err)

		response := presentationRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.VerifiablePresentation)

		vp, err := verifiableapi.ParsePresentation(response.VerifiablePresentation,
			verifiableapi.WithPresDisabledProofCheck())

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.NotEmpty(t, vp.Proofs)
		require.Len(t, vp.Proofs, 1)
		require.Equal(t, vp.Proofs[0]["challenge"], presReq.Challenge)
		require.Equal(t, vp.Proofs[0]["domain"], presReq.Domain)
		require.Equal(t, vp.Proofs[0]["proofPurpose"], "authentication")
		require.Contains(t, vp.Proofs[0]["created"], strconv.Itoa(presReq.Created.Year()))
	})

	t.Run("test generate verifiable presentation from presentation with options  - success", func(t *testing.T) {
		pRaw := json.RawMessage(`{"@context": "https://www.w3.org/2018/credentials/v1",
		"type": "VerifiablePresentation","holder": "did:web:vc.example.world"}`)

		createdTime := time.Now().AddDate(-1, 0, 0)
		presReq := verifiable.PresentationRequest{
			Presentation: pRaw,
			DID:          "did:peer:21tDAKCERh95uGgKbJNHYp",
			ProofOptions: &verifiable.ProofOptions{
				VerificationMethod: "did:peer:123456789abcdefghi#keys-1",
				Domain:             "issuer.example.com",
				Challenge:          "sample-random-test-value",
				Created:            &createdTime,
				SignatureType:      verifiable.Ed25519Signature2018,
			},
		}
		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, GeneratePresentationPath, http.MethodPost)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(presReqBytes), handler.Path())
		require.NoError(t, err)

		response := presentationRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.VerifiablePresentation)

		vp, err := verifiableapi.ParsePresentation(response.VerifiablePresentation,
			verifiableapi.WithPresDisabledProofCheck())

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.NotEmpty(t, vp.Proofs)
		require.Equal(t, vp.Holder, "did:peer:21tDAKCERh95uGgKbJNHYp")
		require.Len(t, vp.Proofs, 1)
		require.Equal(t, vp.Proofs[0]["challenge"], presReq.Challenge)
		require.Equal(t, vp.Proofs[0]["domain"], presReq.Domain)
		require.Equal(t, vp.Proofs[0]["proofPurpose"], "authentication")
		require.Contains(t, vp.Proofs[0]["created"], strconv.Itoa(presReq.Created.Year()))
	})

	t.Run("test generate presentation - error", func(t *testing.T) {
		var jsonStr = []byte(`{
			"name" : "sample",
			"signatureType":"Ed25519Signature2018",
            "did"  : "did:peer:21tDAKCERh95uGgKbJNHYp"
		}`)

		handler := lookupHandler(t, cmd, GeneratePresentationPath, http.MethodPost)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, verifiable.GeneratePresentationErrorCode,
			"no valid credentials/presentation found", buf.Bytes())
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

	t.Run("test generate presentation by id - success", func(t *testing.T) {
		// to store the values in the store
		s["http://example.edu/credentials/1989"] = []byte(vc)
		s["did:peer:21tDAKCERh95uGgKbJNHYp"] = []byte(doc)

		presReqByID := verifiable.PresentationRequestByID{
			ID:            "http://example.edu/credentials/1989",
			DID:           "did:peer:21tDAKCERh95uGgKbJNHYp",
			SignatureType: verifiable.Ed25519Signature2018,
		}
		presReqBytes, err := json.Marshal(presReqByID)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, GeneratePresentationByIDPath, http.MethodPost)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(presReqBytes), handler.Path())
		require.NoError(t, err)

		response := presentationRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.VerifiablePresentation)
	})

	t.Run("test generate presentation by id - invalid data", func(t *testing.T) {
		var jsonStr = []byte(`{
			"id" : "sample", 
     		"did": "testDID"
		}`)

		handler := lookupHandler(t, cmd, GeneratePresentationByIDPath, http.MethodPost)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, verifiable.GeneratePresentationByIDErrorCode, "get vc by id ", buf.Bytes())
	})

	t.Run("test generate presentation by id - invalid did", func(t *testing.T) {
		var jsonStr = []byte(`{
			"name" : "http://example.edu/credentials/1989", 
     		"dids": "testDID"
		}`)

		handler := lookupHandler(t, cmd, GeneratePresentationByIDPath, http.MethodPost)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, verifiable.InvalidRequestErrorCode, "credential id is mandatory", buf.Bytes())
	})
}

func TestSaveVP(t *testing.T) {
	t.Run("test save vp - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		presentations := []string{udPresentation, udVerifiablePresentation}
		handler := lookupHandler(t, cmd, SavePresentationPath, http.MethodPost)

		for i, presentation := range presentations {
			vpReq := verifiable.PresentationExt{
				Presentation: verifiable.Presentation{VerifiablePresentation: stringToJSONRaw(presentation)},
				Name:         fmt.Sprintf("%s_%d", samplePresentationName, i),
			}
			jsonStr, err := json.Marshal(vpReq)
			require.NoError(t, err)

			buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
			require.NoError(t, err)

			response := emptyRes{}
			err = json.Unmarshal(buf.Bytes(), &response)
			require.NoError(t, err)

			// verify response
			require.Empty(t, response)
		}
	})

	t.Run("test save vp - error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var jsonStr = []byte(`{
			"name" : "sample"
		}`)

		handler := lookupHandler(t, cmd, SavePresentationPath, http.MethodPost)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, verifiable.SavePresentationErrorCode, "parse vp :", buf.Bytes())
	})
}

func TestGetVP(t *testing.T) {
	t.Run("test get vp - success", func(t *testing.T) {
		s := make(map[string][]byte)
		s[sampleVPID] = []byte(vc)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handler := lookupHandler(t, cmd, SavePresentationPath, http.MethodPost)

		vpReq := verifiable.PresentationExt{
			Presentation: verifiable.Presentation{VerifiablePresentation: stringToJSONRaw(udPresentation)},
			Name:         samplePresentationName,
		}
		jsonStr, err := json.Marshal(vpReq)
		require.NoError(t, err)

		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)

		response := emptyRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.Empty(t, response)

		handler = lookupHandler(t, cmd, GetPresentationPath, http.MethodGet)

		buf, err = getSuccessResponseFromHandler(handler, nil, fmt.Sprintf(`%s/%s`,
			verifiablePresentationPath, base64.StdEncoding.EncodeToString([]byte(sampleVPID))))
		require.NoError(t, err)

		getResponse := presentationRes{}
		err = json.Unmarshal(buf.Bytes(), &getResponse)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, getResponse)
	})

	t.Run("test get vp - error", func(t *testing.T) {
		s := make(map[string][]byte)
		s[sampleVPID] = []byte(vc)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handler := lookupHandler(t, cmd, GetPresentationPath, http.MethodGet)
		buf, code, err := sendRequestToHandler(handler, nil, fmt.Sprintf(`%s/%s`, verifiablePresentationPath, "abc"))
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, verifiable.InvalidRequestErrorCode, "illegal base64 data", buf.Bytes())
	})
}

func TestGetPresentations(t *testing.T) {
	t.Run("test get presentations", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		presentations := []string{udPresentation, udVerifiablePresentation}
		handler := lookupHandler(t, cmd, SavePresentationPath, http.MethodPost)

		for i, presentation := range presentations {
			vpReq := verifiable.PresentationExt{
				Presentation: verifiable.Presentation{VerifiablePresentation: stringToJSONRaw(presentation)},
				Name:         fmt.Sprintf("%s_%d", samplePresentationName, i),
			}
			jsonStr, e := json.Marshal(vpReq)
			require.NoError(t, e)

			buf, e := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
			require.NoError(t, e)

			response := emptyRes{}
			e = json.Unmarshal(buf.Bytes(), &response)
			require.NoError(t, e)

			// verify response
			require.Empty(t, response)
		}

		handler = lookupHandler(t, cmd, GetPresentationsPath, http.MethodGet)
		buf, err := getSuccessResponseFromHandler(handler, nil, GetPresentationsPath)
		require.NoError(t, err)

		var response presentationRecordResult
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.Equal(t, 2, len(response.Result))
		require.Len(t, response.Result[0].Context, 2)
		require.Len(t, response.Result[0].Type, 1)
	})
}

func TestSignCredential(t *testing.T) {
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

	t.Run("test sign credential - success", func(t *testing.T) {
		req := verifiable.SignCredentialRequest{
			Credential: []byte(vc),
			DID:        "did:peer:21tDAKCERh95uGgKbJNHYp",
			ProofOptions: &verifiable.ProofOptions{
				SignatureType: verifiable.Ed25519Signature2018,
			},
		}

		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, SignCredentialsPath, http.MethodPost)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(reqBytes), handler.Path())
		require.NoError(t, err, err)

		response := signCredentialRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.VerifiableCredential)
	})

	t.Run("test sign credential with options - success", func(t *testing.T) {
		createdTime := time.Now().AddDate(-1, 0, 0)
		req := verifiable.SignCredentialRequest{
			Credential: []byte(vc),
			DID:        "did:peer:21tDAKCERh95uGgKbJNHYp",
			ProofOptions: &verifiable.ProofOptions{
				VerificationMethod: "did:peer:123456789abcdefghi#keys-1",
				Domain:             "issuer.example.com",
				Challenge:          "sample-random-test-value",
				Created:            &createdTime,
				SignatureType:      verifiable.Ed25519Signature2018,
			},
		}
		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, SignCredentialsPath, http.MethodPost)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(reqBytes), handler.Path())
		require.NoError(t, err)

		response := signCredentialRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.VerifiableCredential)

		vp, err := verifiableapi.ParseCredential(response.VerifiableCredential,
			verifiableapi.WithDisabledProofCheck())

		require.NoError(t, err)
		require.NotNil(t, vp)
		require.NotEmpty(t, vp.Proofs)
		require.Len(t, vp.Proofs, 1)
		require.Equal(t, vp.Proofs[0]["challenge"], req.Challenge)
		require.Equal(t, vp.Proofs[0]["domain"], req.Domain)
		require.Equal(t, vp.Proofs[0]["proofPurpose"], "assertionMethod")
		require.Contains(t, vp.Proofs[0]["created"], strconv.Itoa(req.Created.Year()))
	})

	t.Run("test sign credential using options  - success", func(t *testing.T) {
		createdTime := time.Now().AddDate(-1, 0, 0)
		req := verifiable.SignCredentialRequest{
			Credential: []byte(vc),
			DID:        "did:peer:21tDAKCERh95uGgKbJNHYp",
			ProofOptions: &verifiable.ProofOptions{
				VerificationMethod: "did:peer:123456789abcdefghi#keys-1",
				Domain:             "issuer.example.com",
				Challenge:          "sample-random-test-value",
				Created:            &createdTime,
				SignatureType:      verifiable.Ed25519Signature2018,
			},
		}
		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, SignCredentialsPath, http.MethodPost)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(reqBytes), handler.Path())
		require.NoError(t, err)

		response := signCredentialRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.VerifiableCredential)

		vc, err := verifiableapi.ParseCredential(response.VerifiableCredential,
			verifiableapi.WithDisabledProofCheck())

		require.NoError(t, err)
		require.NotNil(t, vc)
		require.NotEmpty(t, vc.Proofs)
		require.Len(t, vc.Proofs, 1)
		require.Equal(t, vc.Proofs[0]["challenge"], req.Challenge)
		require.Equal(t, vc.Proofs[0]["domain"], req.Domain)
		require.Equal(t, vc.Proofs[0]["proofPurpose"], "assertionMethod")
		require.Contains(t, vc.Proofs[0]["created"], strconv.Itoa(req.Created.Year()))
	})

	t.Run("test sign credential - error", func(t *testing.T) {
		var jsonStr = []byte(`{
			"name" : "sample",
            "did"  : "did:peer:21tDAKCERh95uGgKbJNHYp"
		}`)

		handler := lookupHandler(t, cmd, SignCredentialsPath, http.MethodPost)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, verifiable.SignCredentialErrorCode,
			"parse vc : unmarshal new credential", buf.Bytes())
	})
}

func TestRemoveVCByName(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		vcReq := verifiable.CredentialExt{
			Credential: verifiable.Credential{VerifiableCredential: vc},
			Name:       sampleCredentialName,
		}
		jsonStr, err := json.Marshal(vcReq)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, SaveCredentialPath, http.MethodPost)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		handler = lookupHandler(t, cmd, RemoveCredentialByNamePath, http.MethodPost)
		_, err = getSuccessResponseFromHandler(handler, nil, fmt.Sprintf(`%s/remove/name/%s`,
			verifiableCredentialPath, sampleCredentialName))
		require.NoError(t, err)
	})

	t.Run("error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handler := lookupHandler(t, cmd, RemoveCredentialByNamePath, http.MethodPost)
		buf, code, err := sendRequestToHandler(handler, nil, fmt.Sprintf(`%s/remove/name/%s`,
			verifiableCredentialPath, sampleCredentialName))
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, verifiable.RemoveCredentialByNameErrorCode, "remove vc by name", buf.Bytes())
	})
}

func TestRemoveVPByName(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s := make(map[string][]byte)
		s[sampleVPID] = []byte(vc)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handler := lookupHandler(t, cmd, SavePresentationPath, http.MethodPost)

		vpReq := verifiable.PresentationExt{
			Presentation: verifiable.Presentation{VerifiablePresentation: stringToJSONRaw(udPresentation)},
			Name:         samplePresentationName,
		}
		jsonStr, err := json.Marshal(vpReq)
		require.NoError(t, err)

		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)

		response := emptyRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.Empty(t, response)

		handler = lookupHandler(t, cmd, RemovePresentationByNamePath, http.MethodPost)

		_, err = getSuccessResponseFromHandler(handler, nil, fmt.Sprintf(`%s/remove/name/%s`,
			verifiablePresentationPath, samplePresentationName))
		require.NoError(t, err)
	})

	t.Run("error", func(t *testing.T) {
		s := make(map[string][]byte)
		s[sampleVPID] = []byte(vc)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handler := lookupHandler(t, cmd, RemovePresentationByNamePath, http.MethodPost)
		buf, code, err := sendRequestToHandler(handler, nil,
			fmt.Sprintf(`%s/remove/name/%s`, verifiablePresentationPath, samplePresentationName))
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, verifiable.RemovePresentationByNameErrorCode, "remove vp by name", buf.Bytes())
	})
}

func lookupHandler(t *testing.T, op *Operation, path, method string) rest.Handler {
	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == path && h.Method() == method {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

// getSuccessResponseFromHandler reads response from given http handle func.
// expects http status OK.
func getSuccessResponseFromHandler(handler rest.Handler, requestBody io.Reader,
	path string) (*bytes.Buffer, error) {
	response, status, err := sendRequestToHandler(handler, requestBody, path)
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: got %v, want %v",
			status, http.StatusOK)
	}

	return response, err
}

// sendRequestToHandler reads response from given http handle func.
func sendRequestToHandler(handler rest.Handler, requestBody io.Reader, path string) (*bytes.Buffer, int, error) {
	// prepare request
	req, err := http.NewRequest(handler.Method(), path, requestBody)
	if err != nil {
		return nil, 0, err
	}

	// prepare router
	router := mux.NewRouter()

	router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())

	// create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()

	// serve http on given response and request
	router.ServeHTTP(rr, req)

	return rr.Body, rr.Code, nil
}

func verifyError(t *testing.T, expectedCode command.Code, expectedMsg string, data []byte) {
	// Parser generic error response
	errResponse := struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{}
	err := json.Unmarshal(data, &errResponse)
	require.NoError(t, err)

	// verify response
	require.EqualValues(t, expectedCode, errResponse.Code)
	require.NotEmpty(t, errResponse.Message)

	if expectedMsg != "" {
		require.Contains(t, errResponse.Message, expectedMsg)
	}
}

func stringToJSONRaw(jsonStr string) json.RawMessage {
	return []byte(jsonStr)
}
