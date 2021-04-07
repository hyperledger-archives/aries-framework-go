/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	mediatorSvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	messagepickupSvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/messagepickup"
	oobsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/messagepickup"
	mockoob "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/outofband"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

const (
	connIDRequest = `{"connectionID":"abc-123"}`
)

func TestNew(t *testing.T) {
	t.Run("test new command", func(t *testing.T) {
		cmd, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, cmd)
	})

	t.Run("test new command - command creation fail", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{},
			false,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "create route command")
		require.Nil(t, cmd)
	})
}

func TestOperation_GetRESTHandlers(t *testing.T) {
	svc, err := New(newMockProvider(nil), false)
	require.NoError(t, err)
	require.NotNil(t, svc)

	handlers := svc.GetRESTHandlers()
	require.Equal(t, len(handlers), 7)
}

func TestOperation_Register(t *testing.T) {
	t.Run("test register route - success", func(t *testing.T) {
		svc, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, svc)

		jsonStr := []byte(connIDRequest)

		handler := lookupHandler(t, svc, RegisterPath)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)

		response := registerRouteRes{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.Empty(t, response)
	})

	t.Run("test register route - missing connectionID", func(t *testing.T) {
		svc, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, svc)

		jsonStr := []byte(`{
		}`)

		handler := lookupHandler(t, svc, RegisterPath)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, mediator.RegisterMissingConnIDCode, "connectionID is mandatory", buf.Bytes())
	})
}

func TestOperation_Unregister(t *testing.T) {
	t.Run("test unregister route - success", func(t *testing.T) {
		svc, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, svc)

		handler := lookupHandler(t, svc, UnregisterPath)
		_, err = getSuccessResponseFromHandler(handler,
			bytes.NewBuffer([]byte(`{"connectionID":"xyz"}`)), handler.Path())
		require.NoError(t, err)
	})

	t.Run("test unregister route - missing connectionID", func(t *testing.T) {
		svc, err := New(
			newMockProvider(map[string]interface{}{
				messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
				mediatorSvc.Coordination: &mockroute.MockMediatorSvc{
					UnregisterErr: errors.New("unregister error"),
				},
				oobsvc.Name: &mockoob.MockOobService{},
			}),
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, svc)

		jsonStr := []byte(`{"connectionID":"xyz"}`)

		handler := lookupHandler(t, svc, UnregisterPath)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusInternalServerError, code)
		verifyError(t, mediator.UnregisterRouterErrorCode, "router unregister", buf.Bytes())
	})
}

func TestOperation_Connection(t *testing.T) {
	t.Run("test get connection - success", func(t *testing.T) {
		routerConnectionID := "conn-abc"
		svc, err := New(
			newMockProvider(map[string]interface{}{
				messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
				mediatorSvc.Coordination: &mockroute.MockMediatorSvc{
					Connections: []string{routerConnectionID},
				},
				oobsvc.Name: &mockoob.MockOobService{},
			}),
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, svc)

		handler := lookupHandler(t, svc, GetConnectionsPath)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer([]byte("")), handler.Path())
		require.NoError(t, err)

		response := mediator.ConnectionsResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response.Connections)
	})

	t.Run("test get connection - missing connectionID", func(t *testing.T) {
		svc, err := New(
			newMockProvider(map[string]interface{}{
				messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
				mediatorSvc.Coordination: &mockroute.MockMediatorSvc{
					GetConnectionsErr: errors.New("get connections error"),
				},
				oobsvc.Name: &mockoob.MockOobService{},
			}),
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, svc)

		jsonStr := []byte(`{
		}`)

		handler := lookupHandler(t, svc, GetConnectionsPath)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusInternalServerError, code)
		verifyError(t, mediator.GetConnectionsErrorCode, "get connections error", buf.Bytes())
	})
}

func TestOperation_Reconnect(t *testing.T) {
	t.Run("test register route - success", func(t *testing.T) {
		svc, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, svc)

		jsonStr := []byte(connIDRequest)

		handler := lookupHandler(t, svc, ReconnectPath)
		_, err = getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
	})

	t.Run("test register route - missing connectionID", func(t *testing.T) {
		svc, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, svc)

		jsonStr := []byte(`{
		}`)

		handler := lookupHandler(t, svc, ReconnectPath)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, mediator.ReconnectMissingConnIDCode, "connectionID is mandatory", buf.Bytes())
	})
}

func TestOperation_Status(t *testing.T) {
	t.Run("test status - success", func(t *testing.T) {
		const sampleID = "sample-status-id"
		const size = 64
		svc, err := New(
			newMockProvider(map[string]interface{}{
				messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{
					StatusRequestFunc: func(connectionID string) (*messagepickupSvc.Status, error) {
						return &messagepickupSvc.Status{ID: sampleID, TotalSize: size, MessageCount: size - 10}, nil
					},
				},
				mediatorSvc.Coordination: &mockroute.MockMediatorSvc{},
				oobsvc.Name:              &mockoob.MockOobService{},
			}),
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, svc)

		handler := lookupHandler(t, svc, StatusPath)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer([]byte(connIDRequest)), handler.Path())
		require.NoError(t, err)

		response := statusResponse{}
		err = json.Unmarshal(buf.Bytes(), &response.Params)
		require.NoError(t, err)
		require.NotEmpty(t, response.Params)
		require.Equal(t, size, response.Params.TotalSize)
		require.Equal(t, size-10, response.Params.MessageCount)
		require.Equal(t, sampleID, response.Params.ID)
	})

	t.Run("test status - missing connectionID", func(t *testing.T) {
		svc, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, svc)

		handler := lookupHandler(t, svc, StatusPath)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer([]byte(`{}`)), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, mediator.StatusRequestMissingConnIDCode, "connectionID is mandatory", buf.Bytes())
	})
}

func TestOperation_BatchPickup(t *testing.T) {
	t.Run("test batchpickup - success", func(t *testing.T) {
		const count = 64
		svc, err := New(
			newMockProvider(map[string]interface{}{
				messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{
					BatchPickupFunc: func(connectionID string, size int) (int, error) {
						return count, nil
					},
				},
				mediatorSvc.Coordination: &mockroute.MockMediatorSvc{},
				oobsvc.Name:              &mockoob.MockOobService{},
			}),
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, svc)

		handler := lookupHandler(t, svc, BatchPickupPath)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer([]byte(connIDRequest)), handler.Path())
		require.NoError(t, err)

		response := batchPickupResponse{}
		err = json.Unmarshal(buf.Bytes(), &response.Params)
		require.NoError(t, err)
		require.NotEmpty(t, response.Params)
		require.Equal(t, count, response.Params.MessageCount)
	})

	t.Run("test status - missing connectionID", func(t *testing.T) {
		svc, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, svc)

		handler := lookupHandler(t, svc, BatchPickupPath)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer([]byte(`{}`)), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)

		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, mediator.BatchPickupMissingConnIDCode, "connectionID is mandatory", buf.Bytes())
	})
}

func newMockProvider(serviceMap map[string]interface{}) *mockprovider.Provider {
	if serviceMap == nil {
		serviceMap = map[string]interface{}{
			mediatorSvc.Coordination:       &mockroute.MockMediatorSvc{},
			oobsvc.Name:                    &mockoob.MockOobService{},
			messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
		}
	}

	return &mockprovider.Provider{
		ServiceMap:                        serviceMap,
		StorageProviderValue:              mockstorage.NewMockStoreProvider(),
		ProtocolStateStorageProviderValue: mockstorage.NewMockStoreProvider(),
		KMSValue:                          &mockkms.KeyManager{},
	}
}

func lookupHandler(t *testing.T, op *Operation, path string) rest.Handler {
	t.Helper()

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
