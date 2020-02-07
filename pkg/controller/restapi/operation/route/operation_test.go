/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

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
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/route"
	"github.com/hyperledger/aries-framework-go/pkg/controller/restapi/operation"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol/route"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
)

func TestNew(t *testing.T) {
	t.Run("test new command", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceValue: &mockroute.MockRouteSvc{},
			},
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)
	})

	t.Run("test new command - command creation fail", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "create route command")
		require.Nil(t, cmd)
	})
}

func TestGetAPIHandlers(t *testing.T) {
	svc, err := New(
		&mockprovider.Provider{
			ServiceValue: &mockroute.MockRouteSvc{},
		},
	)
	require.NoError(t, err)
	require.NotNil(t, svc)

	handlers := svc.GetRESTHandlers()
	require.Equal(t, len(handlers), 1)
}

func TestRegisterRoute(t *testing.T) {
	t.Run("test register route - success", func(t *testing.T) {
		svc, err := New(
			&mockprovider.Provider{
				ServiceValue: &mockroute.MockRouteSvc{},
			},
		)
		require.NoError(t, err)
		require.NotNil(t, svc)

		var jsonStr = []byte(`{
		"connectionID":"abc-123"
		}`)

		handler := lookupCreatePublicDIDHandler(t, svc)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)

		response := registerRouteRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.Empty(t, response)
	})

	t.Run("test register route - missing connectionID", func(t *testing.T) {
		svc, err := New(
			&mockprovider.Provider{
				ServiceValue: &mockroute.MockRouteSvc{},
			},
		)
		require.NoError(t, err)
		require.NotNil(t, svc)

		var jsonStr = []byte(`{
		}`)

		handler := lookupCreatePublicDIDHandler(t, svc)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, route.RegisterMissingConnIDCode, "connectionID is mandatory", buf.Bytes())
	})
}

func lookupCreatePublicDIDHandler(t *testing.T, op *Operation) operation.Handler {
	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == registerPath {
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
