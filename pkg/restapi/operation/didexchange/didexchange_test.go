/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	didexsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/common/did"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	mockwallet "github.com/hyperledger/aries-framework-go/pkg/internal/mock/wallet"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation/didexchange/models"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/webhook"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

func TestOperation_GetAPIHandlers(t *testing.T) {
	svc, err := New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(),
		ServiceValue: &protocol.MockDIDExchangeSvc{}}, webhook.NewHTTPNotifier(nil))
	require.NoError(t, err)
	require.NotNil(t, svc)

	handlers := svc.GetRESTHandlers()
	require.NotEmpty(t, handlers)
}

func TestNew_Fail(t *testing.T) {
	svc, err := New(&mockprovider.Provider{ServiceErr: errors.New("test-error")}, webhook.NewHTTPNotifier(nil))
	require.Error(t, err)
	require.Nil(t, svc)
}

func TestOperation_CreateInvitation(t *testing.T) {
	handler := getHandler(t, createInvitationPath, nil)
	buf, err := getResponseFromHandler(handler, nil, handler.Path())
	require.NoError(t, err)

	response := models.CreateInvitationResponse{}
	err = json.Unmarshal(buf.Bytes(), &response)
	require.NoError(t, err)

	// verify response
	require.NotEmpty(t, response.Payload)
	require.Equal(t, "endpoint", response.Payload.ServiceEndpoint)
	require.NotEmpty(t, response.Payload.Label)
}

func TestOperation_ReceiveInvitation(t *testing.T) {
	var jsonStr = []byte(`{
    	"@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation",
    	"@id": "4e8650d9-6cc9-491e-b00e-7bf6cb5858fc",
    	"serviceEndpoint": "http://ip10-0-46-4-blikjbs9psqg8vrg4p10-8020.direct.play-with-von.vonx.io",
    	"label": "Faber Agent",
    	"recipientKeys": [
      		"6LE8yhZB8Xffc5vFgFntE3YLrxq5JVUsoAvUQgUyktGt"
    		]
  	}`)

	handler := getHandler(t, receiveInvtiationPath, nil)
	buf, err := getResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
	require.NoError(t, err)

	response := models.ReceiveInvitationResponse{}
	err = json.Unmarshal(buf.Bytes(), &response)
	require.NoError(t, err)

	// verify response
	require.NotEmpty(t, response)
	require.NotEmpty(t, response.ConnectionID)
	require.NotEmpty(t, response.CreateTime)
	require.NotEmpty(t, response.UpdateTime)
	require.NotEmpty(t, response.RequestID)
	require.NotEmpty(t, response.DID)
}

func TestOperation_QueryConnectionByID(t *testing.T) {
	handler := getHandler(t, connectionsByID, nil)
	buf, err := getResponseFromHandler(handler, bytes.NewBuffer([]byte("sample-connection-id")), operationID+"/1234")
	require.NoError(t, err)

	response := models.QueryConnectionResponse{}
	err = json.Unmarshal(buf.Bytes(), &response)
	require.NoError(t, err)

	// verify response
	require.NotEmpty(t, response)
	require.NotEmpty(t, response.Result)
	require.NotEmpty(t, response.Result.ConnectionID)
}

func TestOperation_QueryConnectionByParams(t *testing.T) {
	handler := getHandler(t, connections, nil)
	buf, err := getResponseFromHandler(handler, nil,
		operationID+"?invitation_key=3nPvih&alias=sample&state=completed&initiator=test")
	require.NoError(t, err)

	response := models.QueryConnectionsResponse{}
	err = json.Unmarshal(buf.Bytes(), &response)
	require.NoError(t, err)

	// verify response
	require.NotEmpty(t, response)
	require.NotEmpty(t, response.Body)
	require.NotEmpty(t, response.Body.Results)
	for _, result := range response.Body.Results {
		require.NotNil(t, result)
		require.NotNil(t, result.ConnectionID)
	}
}

func TestOperation_ReceiveInvitationFailure(t *testing.T) {
	verifyError := func(data []byte) {
		response := models.ReceiveInvitationResponse{}
		err := json.Unmarshal(data, &response)
		require.NoError(t, err)

		// verify response
		require.Empty(t, response.DID)
		require.Empty(t, response.CreateTime)
		require.Empty(t, response.UpdateTime)
		require.Empty(t, response.RequestID)

		// Parser generic error response
		errResponse := models.GenericError{}
		err = json.Unmarshal(data, &errResponse)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, errResponse.Body)
		require.NotEmpty(t, errResponse.Body.Code)
		require.NotEmpty(t, errResponse.Body.Message)
	}

	// Failure in service
	var jsonStr = []byte(`{
    	"@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation",
    	"@id": "4e8650d9-6cc9-491e-b00e-7bf6cb5858fc",
    	"serviceEndpoint": "http://ip10-0-46-4-blikjbs9psqg8vrg4p10-8020.direct.play-with-von.vonx.io",
    	"label": "Faber Agent",
    	"recipientKeys": [
      		"6LE8yhZB8Xffc5vFgFntE3YLrxq5JVUsoAvUQgUyktGt"
    		]
  	}`)
	handler := getHandler(t, receiveInvtiationPath, errors.New("handler failed"))
	buf, err := getResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
	require.NoError(t, err)
	verifyError(buf.Bytes())

	// Failure due to invalid request body
	jsonStr = []byte("")
	handler = getHandler(t, receiveInvtiationPath, nil)
	buf, err = getResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
	require.NoError(t, err)
	verifyError(buf.Bytes())
}

func TestOperation_AcceptInvitation(t *testing.T) {
	handler := getHandler(t, acceptInvitationPath, nil)
	buf, err := getResponseFromHandler(handler, bytes.NewBuffer([]byte("test-id")), operationID+"/1111/accept-invitation")
	require.NoError(t, err)

	response := models.AcceptInvitationResponse{}
	err = json.Unmarshal(buf.Bytes(), &response)
	require.NoError(t, err)

	// verify response
	require.NotEmpty(t, response)
	require.NotEmpty(t, response.ConnectionID)
	require.NotEmpty(t, response.CreateTime)
	require.NotEmpty(t, response.UpdateTime)
	require.NotEmpty(t, response.RequestID)
	require.NotEmpty(t, response.DID)
}

func TestOperation_AcceptExchangeRequest(t *testing.T) {
	handler := getHandler(t, acceptExchangeRequest, nil)
	buf, err := getResponseFromHandler(handler, bytes.NewBuffer([]byte("test-id")), operationID+"/4444/accept-request")
	require.NoError(t, err)

	response := models.AcceptExchangeResult{}
	err = json.Unmarshal(buf.Bytes(), &response)
	require.NoError(t, err)

	// verify response
	require.NotEmpty(t, response)
	require.NotEmpty(t, response.Result.ConnectionID)
	require.NotEmpty(t, response.Result.CreatedTime)
}

func TestOperation_RemoveConnection(t *testing.T) {
	handler := getHandler(t, removeConnection, nil)
	buf, err := getResponseFromHandler(handler, bytes.NewBuffer([]byte("test-id")), operationID+"/5555/remove")
	require.NoError(t, err)
	require.Empty(t, buf.Bytes())
}

func TestOperation_WriteGenericError(t *testing.T) {
	const errMsg = "sample-error-msg"

	svc, err := New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(),
		ServiceValue: &protocol.MockDIDExchangeSvc{}}, webhook.NewHTTPNotifier(nil))
	require.NoError(t, err)
	require.NotNil(t, svc)

	rr := httptest.NewRecorder()

	err = errors.New(errMsg)
	svc.writeGenericError(rr, err)

	response := models.GenericError{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)

	require.NoError(t, err)
	require.NotEmpty(t, response.Body)
	require.NotEmpty(t, response.Body.Message)
	require.Equal(t, response.Body.Message, errMsg)
	require.NotEmpty(t, response.Body.Code)
}

func TestOperation_WriteResponse(t *testing.T) {
	svc, err := New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(),
		ServiceValue: &protocol.MockDIDExchangeSvc{}}, webhook.NewHTTPNotifier(nil))
	require.NoError(t, err)
	require.NotNil(t, svc)
	svc.writeResponse(&mockWriter{errors.New("failed to write")}, &models.QueryConnectionResponse{})
}

// getResponseFromHandler reads response from given http handle func
func getResponseFromHandler(handler operation.Handler, requestBody io.Reader, path string) (*bytes.Buffer, error) {
	// prepare request
	req, err := http.NewRequest(handler.Method(), path, requestBody)
	if err != nil {
		return nil, err
	}

	// prepare router
	router := mux.NewRouter()

	router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())

	// create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()

	// serve http on given response and request
	router.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		return nil, fmt.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	return rr.Body, nil
}

func getHandler(t *testing.T, lookup string, handleErr error) operation.Handler {
	s := mockstore.MockStore{Store: make(map[string][]byte)}
	require.NoError(t, s.Put("1234", []byte("complete")))
	svc, err := New(&mockprovider.Provider{
		ServiceValue: &protocol.MockDIDExchangeSvc{
			ProtocolName: "mockProtocolSvc",
			HandleFunc: func(msg service.DIDCommMsg) error {
				return handleErr
			},
		},
		WalletValue:          &mockwallet.CloseableWallet{CreateEncryptionKeyValue: "sample-key"},
		InboundEndpointValue: "endpoint",
		StorageProviderValue: &mockstore.MockStoreProvider{Store: &s}},
		webhook.NewHTTPNotifier(nil),
	)
	require.NoError(t, err)
	require.NotNil(t, svc)

	handlers := svc.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == lookup {
			return h
		}
	}
	require.Fail(t, "unable to find handler")
	return nil
}

type mockWriter struct {
	failure error
}

func (m mockWriter) Write([]byte) (int, error) {
	return 0, m.failure
}

func TestServiceEvents(t *testing.T) {
	store := &mockstore.MockStore{Store: make(map[string][]byte)}
	didExSvc, err := didexsvc.New(&did.MockDIDCreator{}, &protocol.MockProvider{CustomStore: store})
	require.NoError(t, err)

	// create the client
	op, err := New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(),
		ServiceValue: didExSvc}, webhook.NewHTTPNotifier(nil))
	require.NoError(t, err)
	require.NotNil(t, op)

	// send connection request message
	id := "valid-thread-id"
	newDidDoc, err := (&did.MockDIDCreator{}).CreateDID()
	require.NoError(t, err)

	request, err := json.Marshal(
		&didexsvc.Request{
			Type:  didexsvc.ConnectionRequest,
			ID:    id,
			Label: "test",
			Connection: &didexsvc.Connection{
				DID:    "B.did@B:A",
				DIDDoc: newDidDoc,
			},
		},
	)
	require.NoError(t, err)
	msg, err := service.NewDIDCommMsg(request)
	require.NoError(t, err)
	err = didExSvc.HandleInbound(msg)
	require.NoError(t, err)

	validateState(t, store, id, "responded", 100*time.Millisecond)
}

func validateState(t *testing.T, store storage.Store, id, expected string, timeoutDuration time.Duration) {
	actualState := ""
	timeout := time.After(timeoutDuration)
	for {
		select {
		case <-timeout:
			require.Fail(t, fmt.Sprintf("id=%s expectedState=%s actualState=%s", id, expected, actualState))
			return
		default:
			v, err := store.Get(id)
			actualState = string(v)
			if err != nil || expected != string(v) {
				continue
			}
			return
		}
	}
}

func TestOperationEventError(t *testing.T) {
	client, err := didexchange.New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(),
		ServiceValue: &protocol.MockDIDExchangeSvc{}})
	require.NoError(t, err)

	ops := &Operation{client: client}

	aCh := make(chan service.DIDCommAction)
	err = client.RegisterActionEvent(aCh)
	require.NoError(t, err)

	err = ops.startClientEventListener()
	require.Error(t, err)
	require.Contains(t, err.Error(), "didexchange action event registration failed: channel is already "+
		"registered for the action event")

	err = client.UnregisterActionEvent(aCh)
	require.NoError(t, err)
}
