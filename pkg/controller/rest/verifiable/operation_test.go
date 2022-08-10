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
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	verifiableapi "github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	kmsmock "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
)

const (
	sampleCredentialName   = "sampleVCName"
	samplePresentationName = "sampleVPName"
	sampleVCID             = "http://example.edu/credentials/1989"
	sampleVPID             = "http://example.edu/presentations/1989"
	invalidDID             = "did:error:1234"
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

//nolint:lll
const doc = `{
  "@context": ["https://w3id.org/did/v1","https://w3id.org/did/v2"],
  "id": "did:peer:21tDAKCERh95uGgKbJNHYp",
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

func TestNew(t *testing.T) {
	t.Run("test new command - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)
		require.Equal(t, 14, len(cmd.GetRESTHandlers()))
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
		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
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

		jsonStr := []byte(`{
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
		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
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

		jsonStr := []byte(`{
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
		s := make(map[string]mockstore.DBEntry)
		s["http://example.edu/credentials/1989"] = mockstore.DBEntry{Value: []byte(vc)}

		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			DocumentLoaderValue:  loader,
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

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
		s := make(map[string]mockstore.DBEntry)
		s["http://example.edu/credentials/1989"] = mockstore.DBEntry{Value: []byte(vc)}

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
		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
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
		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
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
			"key-1 is not found for DID did:trustbloc:testnet.trustbloc.local:", buf.Bytes())

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
			verifiableapi.WithPresDisabledProofCheck(),
			verifiableapi.WithPresJSONLDDocumentLoader(createTestDocumentLoader(t)))

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
			verifiableapi.WithPresDisabledProofCheck(),
			verifiableapi.WithPresJSONLDDocumentLoader(createTestDocumentLoader(t)))

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
		jsonStr := []byte(`{
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

	t.Run("test generate presentation by id - success", func(t *testing.T) {
		// to store the values in the store
		s["http://example.edu/credentials/1989"] = mockstore.DBEntry{Value: []byte(vc)}
		s["did:peer:21tDAKCERh95uGgKbJNHYp"] = mockstore.DBEntry{Value: []byte(doc)}

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
		jsonStr := []byte(`{
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
		jsonStr := []byte(`{
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
		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
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

		jsonStr := []byte(`{
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
		s := make(map[string]mockstore.DBEntry)
		s[sampleVPID] = mockstore.DBEntry{Value: []byte(vc)}

		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			DocumentLoaderValue:  loader,
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
		s := make(map[string]mockstore.DBEntry)
		s[sampleVPID] = mockstore.DBEntry{Value: []byte(vc)}

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
		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
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
			verifiableapi.WithDisabledProofCheck(),
			verifiableapi.WithJSONLDDocumentLoader(loader))

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
			verifiableapi.WithDisabledProofCheck(),
			verifiableapi.WithJSONLDDocumentLoader(loader))

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
		jsonStr := []byte(`{
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

func TestDeriveCredential(t *testing.T) {
	r := require.New(t)

	loader, err := ldtestutil.DocumentLoader()
	r.NoError(err)

	vc, err := verifiableapi.ParseCredential([]byte(vcForDerive), verifiableapi.WithJSONLDDocumentLoader(loader))
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

	getRequest := func(r *require.Assertions, rq *verifiable.DeriveCredentialRequest) io.Reader {
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

		// call derive credential
		handler := lookupHandler(t, cmd, DeriveCredentialPath, http.MethodPost)
		buf, err := getSuccessResponseFromHandler(handler, getRequest(r, &verifiable.DeriveCredentialRequest{
			Credential: json.RawMessage(requestVC),
			Frame:      frameDoc,
			Nonce:      nonce,
		},
		), handler.Path())
		require.NoError(t, err)

		var response deriveCredentialRes
		err = json.Unmarshal(buf.Bytes(), &response)
		r.NoError(err)

		r.NotEmpty(response)
		r.NotEmpty(response.VerifiableCredential)

		// verify VC
		derived, err := verifiableapi.ParseCredential([]byte(response.VerifiableCredential),
			verifiableapi.WithPublicKeyFetcher(verifiableapi.NewVDRKeyResolver(mockVDR).PublicKeyFetcher()),
			verifiableapi.WithJSONLDDocumentLoader(loader))

		// check expected proof
		r.NoError(err)
		r.NotEmpty(derived)
		r.Len(derived.Proofs, 1)
		r.Equal(derived.Proofs[0]["type"], "BbsBlsSignatureProof2020")
		r.NotEmpty(derived.Proofs[0]["nonce"])
		r.EqualValues(derived.Proofs[0]["nonce"], base64.StdEncoding.EncodeToString([]byte(nonce)))
		r.NotEmpty(derived.Proofs[0]["proofValue"])
	})

	t.Run("derive credential failure", func(t *testing.T) {
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

		// call derive credential
		handler := lookupHandler(t, cmd, DeriveCredentialPath, http.MethodPost)
		buf, code, err := sendRequestToHandler(handler, getRequest(r, &verifiable.DeriveCredentialRequest{
			Credential: json.RawMessage(vcWithDIDNotAvailble),
			Frame:      frameDoc,
			Nonce:      nonce,
			SkipVerify: true,
		},
		), handler.Path())

		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusInternalServerError, code)
		verifyError(t, verifiable.DeriveCredentialErrorCode, "failed to derive credential", buf.Bytes())
	})
}

func TestRemoveVCByName(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
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
		s := make(map[string]mockstore.DBEntry)
		s[sampleVPID] = mockstore.DBEntry{Value: []byte(vc)}

		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			DocumentLoaderValue:  loader,
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
		s := make(map[string]mockstore.DBEntry)
		s[sampleVPID] = mockstore.DBEntry{Value: []byte(vc)}

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
	t.Helper()

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
	t.Helper()

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

// signVCWithBBS signs VC with bbs and returns did used for signing.
func signVCWithBBS(r *require.Assertions, vc *verifiableapi.Credential) string {
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

	ldpContext := &verifiableapi.LinkedDataProofContext{
		SignatureType:           "BbsBlsSignature2020",
		SignatureRepresentation: verifiableapi.SignatureProofValue,
		Suite:                   sigSuite,
		VerificationMethod:      keyID,
	}

	loader, err := ldtestutil.DocumentLoader()
	r.NoError(err)

	err = vc.AddLinkedDataProof(ldpContext, jsonld.WithDocumentLoader(loader))
	r.NoError(err)

	vcSignedBytes, err := json.Marshal(vc)
	r.NoError(err)
	r.NotEmpty(vcSignedBytes)

	vcVerified, err := verifiableapi.ParseCredential(vcSignedBytes,
		verifiableapi.WithEmbeddedSignatureSuites(sigSuite),
		verifiableapi.WithPublicKeyFetcher(verifiableapi.SingleKey(pubKeyBytes, "Bls12381G2Key2020")),
		verifiableapi.WithJSONLDDocumentLoader(loader),
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
