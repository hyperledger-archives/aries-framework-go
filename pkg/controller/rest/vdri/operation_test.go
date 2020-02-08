/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdri

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
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
)

func TestOperation_GetAPIHandlers(t *testing.T) {
	svc := New(&protocol.MockProvider{})
	require.NotNil(t, svc)

	handlers := svc.GetRESTHandlers()
	require.NotEmpty(t, handlers)
}

func TestOperation_CreatePublicDID(t *testing.T) {
	t.Run("Successful Create public DID", func(t *testing.T) {
		svc := New(&protocol.MockProvider{})
		require.NotNil(t, svc)

		handler := lookupCreatePublicDIDHandler(t, svc)
		buf, err := getSuccessResponseFromHandler(handler, nil, handler.Path()+"?method=sidetree")
		require.NoError(t, err)

		response := createPublicDIDResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.DID)
		require.NotEmpty(t, response.DID.ID)
		require.NotEmpty(t, response.DID.PublicKey)
		require.NotEmpty(t, response.DID.Service)
	})

	t.Run("Failed Create public DID", func(t *testing.T) {
		svc := New(&protocol.MockProvider{})
		require.NotNil(t, svc)

		handler := lookupCreatePublicDIDHandler(t, svc)
		buf, code, err := sendRequestToHandler(handler, nil, handler.Path())
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, vdri.InvalidRequestErrorCode, "", buf.Bytes())

		handler = lookupCreatePublicDIDHandler(t, svc)
		buf, code, err = sendRequestToHandler(handler, nil, handler.Path()+"?-----")
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, vdri.InvalidRequestErrorCode, "", buf.Bytes())
	})

	t.Run("Failed Create public DID, VDRI error", func(t *testing.T) {
		svc := New(&protocol.MockProvider{CustomVDRI: &mockvdri.MockVDRIRegistry{CreateErr: fmt.Errorf("just-fail-it")}})
		require.NotNil(t, svc)

		handler := lookupCreatePublicDIDHandler(t, svc)
		buf, code, err := sendRequestToHandler(handler, nil, handler.Path()+"?method=valid")
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, code)
		verifyError(t, vdri.CreatePublicDIDError, "", buf.Bytes())
	})
}

func lookupCreatePublicDIDHandler(t *testing.T, op *Operation) rest.Handler {
	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == createPublicDIDPath {
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
