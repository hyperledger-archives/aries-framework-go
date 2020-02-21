/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"bytes"
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
}`

func TestNew(t *testing.T) {
	cmd := New()
	require.NotNil(t, cmd)
	require.Equal(t, 1, len(cmd.GetRESTHandlers()))
}

func TestValidateVC(t *testing.T) {
	t.Run("test validate vc - success", func(t *testing.T) {
		cmd := New()
		require.NotNil(t, cmd)

		vcReq := verifiable.Credential{VC: vc}
		jsonStr, err := json.Marshal(vcReq)
		require.NoError(t, err)

		handler := lookupHandler(t, cmd, validateCredentialPath)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)

		response := validateCredentialRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.Empty(t, response)
	})

	t.Run("test validate vc - error", func(t *testing.T) {
		cmd := New()
		require.NotNil(t, cmd)

		var jsonStr = []byte(`{
		}`)

		handler := lookupHandler(t, cmd, validateCredentialPath)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, verifiable.ValidateCredentialErrorCode, "new credential : decode new credential", buf.Bytes())
	})
}

func lookupHandler(t *testing.T, op *Operation, path string) rest.Handler {
	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == path {
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
