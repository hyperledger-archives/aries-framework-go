/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

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
}`

func TestNew(t *testing.T) {
	t.Run("test new command - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)
		require.Equal(t, 5, len(cmd.GetRESTHandlers()))
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

		vcReq := verifiable.Credential{VC: vc}
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
		})
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
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		vcReq := verifiable.CredentialExt{
			Credential: verifiable.Credential{VC: vc},
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
		})
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
		verifyError(t, verifiable.SaveCredentialErrorCode, "parse vc : decode new credential", buf.Bytes())
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
		})
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
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		vcReq := verifiable.CredentialExt{
			Credential: verifiable.Credential{VC: vc},
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
		})
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
		})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		vcReq := verifiable.CredentialExt{
			Credential: verifiable.Credential{VC: vc},
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
