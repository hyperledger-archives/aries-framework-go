/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

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

	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/vdri"
	resterrs "github.com/hyperledger/aries-framework-go/pkg/restapi/errors"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation"
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

		response := CreatePublicDIDResponse{}
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
		verifyError(t, InvalidRequestErrorCode, buf.Bytes())

		handler = lookupCreatePublicDIDHandler(t, svc)
		buf, code, err = sendRequestToHandler(handler, nil, handler.Path()+"?-----")
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, InvalidRequestErrorCode, buf.Bytes())
	})

	t.Run("Failed Create public DID, VDRI error", func(t *testing.T) {
		svc := New(&protocol.MockProvider{CustomVDRI: &vdri.MockVDRIRegistry{CreateErr: fmt.Errorf("just-fail-it")}})
		require.NotNil(t, svc)

		handler := lookupCreatePublicDIDHandler(t, svc)
		buf, code, err := sendRequestToHandler(handler, nil, handler.Path()+"?method=valid")
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, code)
		verifyError(t, CreatePublicDIDError, buf.Bytes())
	})
}

func TestBuildSideTreeRequest(t *testing.T) {
	registry := vdri.MockVDRIRegistry{}
	didDoc, err := registry.Create("sidetree")
	require.NoError(t, err)
	require.NotNil(t, didDoc)

	b, err := didDoc.JSONBytes()
	require.NoError(t, err)

	r, err := getBasicRequestBuilder(`{"operation":"create"}`)(b)
	require.NoError(t, err)
	require.NotNil(t, r)
}

func TestOperation_WriteResponse(t *testing.T) {
	svc := New(&protocol.MockProvider{})
	require.NotNil(t, svc)
	svc.writeResponse(&mockWriter{}, CreatePublicDIDResponse{})
}

func lookupCreatePublicDIDHandler(t *testing.T, op *Operation) operation.Handler {
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
func getSuccessResponseFromHandler(handler operation.Handler, requestBody io.Reader,
	path string) (*bytes.Buffer, error) {
	response, status, err := sendRequestToHandler(handler, requestBody, path)
	if status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: got %v, want %v",
			status, http.StatusOK)
	}

	return response, err
}

// sendRequestToHandler reads response from given http handle func.
func sendRequestToHandler(handler operation.Handler, requestBody io.Reader, path string) (*bytes.Buffer, int, error) {
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

func verifyError(t *testing.T, code resterrs.Code, data []byte) {
	// Parser generic error response
	errResponse := struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{}
	err := json.Unmarshal(data, &errResponse)
	require.NoError(t, err)

	// verify response
	require.NotEmpty(t, code, errResponse.Code)
	require.NotEmpty(t, errResponse.Message)
}

type mockWriter struct {
}

func (m *mockWriter) Write(p []byte) (n int, err error) {
	return 0, fmt.Errorf("sample-error")
}
