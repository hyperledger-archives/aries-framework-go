/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	docverifiable "github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	kmsmock "github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

const sampleCredentialName = "sampleVCName"
const sampleVCID = "http://example.edu/credentials/1989"

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
const doc = `{
  "@context": ["https://w3id.org/did/v1","https://w3id.org/did/v2"],
  "id": "did:peer:21tDAKCERh95uGgKbJNHYp",
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

func TestNew(t *testing.T) {
	t.Run("test new command - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		}, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, cmd)
		require.Equal(t, 7, len(cmd.GetRESTHandlers()))
	})

	t.Run("test new command - error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("error opening the store"),
			},
		}, nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "new vc store")
		require.Nil(t, cmd)
	})
}

func TestValidateVC(t *testing.T) {
	t.Run("test validate vc - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		}, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		vcReq := verifiable.Credential{VerifiableCredential: vc}
		jsonStr, err := json.Marshal(vcReq)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, validateCredentialPath, http.MethodPost)
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
		}, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var jsonStr = []byte(`{
		}`)

		handler := lookupHandler(t, cmd, validateCredentialPath, http.MethodPost)
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
		}, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		vcReq := verifiable.CredentialExt{
			Credential: verifiable.Credential{VerifiableCredential: vc},
			Name:       sampleCredentialName,
		}
		jsonStr, err := json.Marshal(vcReq)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, saveCredentialPath, http.MethodPost)
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
		}, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var jsonStr = []byte(`{
			"name" : "sample"
		}`)

		handler := lookupHandler(t, cmd, saveCredentialPath, http.MethodPost)
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
		}, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, cmd)
		fmt.Println(base64.StdEncoding.EncodeToString([]byte("http://example.edu/credentials/1989")))

		handler := lookupHandler(t, cmd, getCredentialPath, http.MethodGet)
		buf, err := getSuccessResponseFromHandler(handler, nil, fmt.Sprintf(`%s/%s`,
			varifiableCredentialPath, base64.StdEncoding.EncodeToString([]byte("http://example.edu/credentials/1989"))))
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
		}, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handler := lookupHandler(t, cmd, getCredentialPath, http.MethodGet)
		buf, code, err := sendRequestToHandler(handler, nil, fmt.Sprintf(`%s/%s`, varifiableCredentialPath, "abc"))
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
		}, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		vcReq := verifiable.CredentialExt{
			Credential: verifiable.Credential{VerifiableCredential: vc},
			Name:       sampleCredentialName,
		}
		jsonStr, err := json.Marshal(vcReq)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, saveCredentialPath, http.MethodPost)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		handler = lookupHandler(t, cmd, getCredentialByNamePath, http.MethodGet)
		buf, err = getSuccessResponseFromHandler(handler, nil, fmt.Sprintf(`%s/name/%s`,
			varifiableCredentialPath, sampleCredentialName))
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
		}, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handler := lookupHandler(t, cmd, getCredentialByNamePath, http.MethodGet)
		buf, code, err := sendRequestToHandler(handler, nil, fmt.Sprintf(`%s/name/%s`,
			varifiableCredentialPath, sampleCredentialName))
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
		}, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		vcReq := verifiable.CredentialExt{
			Credential: verifiable.Credential{VerifiableCredential: vc},
			Name:       sampleCredentialName,
		}
		jsonStr, err := json.Marshal(vcReq)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, saveCredentialPath, http.MethodPost)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		handler = lookupHandler(t, cmd, getCredentialsPath, http.MethodGet)
		buf, err = getSuccessResponseFromHandler(handler, nil, getCredentialsPath)
		require.NoError(t, err)

		var response credentialRecordResult
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.Equal(t, 1, len(response.Result))
	})
}

func TestGeneratePresentation(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cmd, err := New(&mockprovider.Provider{
		StorageProviderValue: mockstore.NewMockStoreProvider(),
	}, &kmsmock.CloseableKMS{},
		&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
			return &verifier.PublicKey{Value: []byte(pubKey)}, nil
		}})
	require.NoError(t, err)
	require.NotNil(t, cmd)

	t.Run("test generate presentation - success", func(t *testing.T) {
		presReq := PresentationRequest{VerifiableCredential: vc, DidDoc: json.RawMessage(doc)}
		presReqBytes, err := json.Marshal(presReq)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, generatePresentationPath, http.MethodPost)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(presReqBytes), handler.Path())
		require.NoError(t, err)

		response := presentationRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.VerifiablePresentation)
	})

	t.Run("test generate presentation - error", func(t *testing.T) {
		var jsonStr = []byte(`{
			"name" : "sample"
		}`)

		handler := lookupHandler(t, cmd, generatePresentationPath, http.MethodPost)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, verifiable.GeneratePresentationErrorCode, "parse vc : decode new credential", buf.Bytes())
	})
}

func TestGeneratePresentationByID(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	s := make(map[string][]byte)

	cmd, err := New(&mockprovider.Provider{
		StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
	}, &kmsmock.CloseableKMS{},
		&mockKeyResolver{publicKeyFetcherValue: func(issuerID, keyID string) (*verifier.PublicKey, error) {
			return &verifier.PublicKey{Value: []byte(pubKey)}, nil
		}})

	require.NoError(t, err)
	require.NotNil(t, cmd)

	t.Run("test generate presentation by id - success", func(t *testing.T) {
		s["http://example.edu/credentials/1989"] = []byte(vc)
		s["did:peer:21tDAKCERh95uGgKbJNHYp"] = []byte(doc)

		handler := lookupHandler(t, cmd, generatePresentationByIDPath, http.MethodGet)
		url := fmt.Sprintf(`%s/%s/%s/%s`,
			varifiableCredentialPath, base64.StdEncoding.EncodeToString([]byte("http://example.edu/credentials/1989")),
			"presentation", base64.StdEncoding.EncodeToString([]byte("did:peer:21tDAKCERh95uGgKbJNHYp")))

		buf, err := getSuccessResponseFromHandler(handler, nil, url)
		require.NoError(t, err)

		response := presentationRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.VerifiablePresentation)
	})

	t.Run("test generate presentation by id - error", func(t *testing.T) {
		handler := lookupHandler(t, cmd, generatePresentationByIDPath, http.MethodGet)
		url := fmt.Sprintf(`%s/%s/%s/%s`, varifiableCredentialPath, "abc",
			"presentation", "testdid")
		buf, code, err := sendRequestToHandler(handler, nil, url)
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, verifiable.InvalidRequestErrorCode, "illegal base64 data", buf.Bytes())
	})

	t.Run("test generate presentation by id - error", func(t *testing.T) {
		handler := lookupHandler(t, cmd, generatePresentationByIDPath, http.MethodGet)
		url := fmt.Sprintf(`%s/%s/%s/%s`, varifiableCredentialPath,
			base64.StdEncoding.EncodeToString([]byte("http://example.edu/credentials/1989")),
			"presentation", "testdid")
		buf, code, err := sendRequestToHandler(handler, nil, url)
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, verifiable.InvalidRequestErrorCode, "illegal base64 data", buf.Bytes())
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

type mockKeyResolver struct {
	publicKeyFetcherValue docverifiable.PublicKeyFetcher
}

func (m *mockKeyResolver) PublicKeyFetcher() docverifiable.PublicKeyFetcher {
	return m.publicKeyFetcherValue
}
