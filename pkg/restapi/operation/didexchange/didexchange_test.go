/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"bytes"
	"crypto"
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
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/internal/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/vdr/didcreator"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation/didexchange/models"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/webhook"
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
	t.Run("Successful CreateInvitation with params", func(t *testing.T) {
		handler := getHandler(t, createInvitationPath, nil)
		buf, err := getResponseFromHandler(handler, nil, handler.Path()+"?alias=mylabel&public=true")
		require.NoError(t, err)

		response := models.CreateInvitationResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response.Invitation)
		require.Equal(t, "endpoint", response.Invitation.ServiceEndpoint)
		require.NotEmpty(t, response.Invitation.Label)
		require.NotEmpty(t, response.Alias)
	})

	t.Run("Successful CreateInvitation with default params", func(t *testing.T) {
		handler := getHandler(t, createInvitationPath, nil)
		buf, err := getResponseFromHandler(handler, nil, handler.Path())
		require.NoError(t, err)

		response := models.CreateInvitationResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response.Invitation)
		require.Equal(t, "endpoint", response.Invitation.ServiceEndpoint)
		require.Empty(t, response.Invitation.Label)
		require.Empty(t, response.Alias)
	})

	t.Run("Failed CreateInvitation with error", func(t *testing.T) {
		handler := getHandler(t, createInvitationPath, nil)
		buf, err := getResponseFromHandler(handler, nil, handler.Path()+"?alias=mylabel&public=345")
		require.NoError(t, err)

		errResponse := models.GenericError{}
		err = json.Unmarshal(buf.Bytes(), &errResponse)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, errResponse.Body)
		require.NotEmpty(t, errResponse.Body.Code)
		require.NotEmpty(t, errResponse.Body.Message)
	})
}

func TestOperation_ReceiveInvitation(t *testing.T) {
	var jsonStr = []byte(`{"invitation":{
		"serviceEndpoint":"http://alice.agent.example.com:8081",
		"recipientKeys":["FDmegH8upiNquathbHZiGBZKwcudNfNWPeGQFBt8eNNi"],
		"@id":"a35c0ac6-4fc3-46af-a072-c1036d036057",
		"label":"agent",
		"@type":"did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/invitation"}}`)

	handler := getHandler(t, receiveInvitationPath, nil)
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
	handler := getHandler(t, receiveInvitationPath, errors.New("handler failed"))
	buf, err := getResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
	require.NoError(t, err)
	verifyError(buf.Bytes())

	// Failure due to invalid request body
	jsonStr = []byte("")
	handler = getHandler(t, receiveInvitationPath, nil)
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
	svc.writeResponse(&httptest.ResponseRecorder{}, &models.QueryConnectionResponse{})
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
	connRec := &didexsvc.ConnectionRecord{State: "complete", ConnectionID: "1234", ThreadID: "th1234"}
	connBytes, err := json.Marshal(connRec)
	require.NoError(t, err)
	require.NoError(t, s.Put("conn_1234", connBytes))
	h := crypto.SHA256.New()
	hash := h.Sum([]byte(connRec.ConnectionID))
	key := fmt.Sprintf("%x", hash)
	require.NoError(t, s.Put("my_"+key, []byte(connRec.ConnectionID)))
	svc, err := New(&mockprovider.Provider{
		ServiceValue: &protocol.MockDIDExchangeSvc{
			ProtocolName: "mockProtocolSvc",
			HandleFunc: func(msg *service.DIDCommMsg) error {
				return handleErr
			},
		},
		KMSValue:             &mockkms.CloseableKMS{CreateEncryptionKeyValue: "sample-key"},
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

func TestServiceEvents(t *testing.T) {
	store := mockstore.NewMockStoreProvider()
	didExSvc, err := didexsvc.New(&didcreator.MockDIDCreator{}, &protocol.MockProvider{StoreProvider: store})

	require.NoError(t, err)

	done := make(chan struct{})

	// create the client
	op, err := New(&mockprovider.Provider{StorageProviderValue: store,
		ServiceValue: didExSvc},
		&mockNotifier{
			notifyFunc: func(topic string, message []byte) error {
				require.Equal(t, connectionsWebhookTopic, topic)

				conn := didexchange.Connection{}
				jsonErr := json.Unmarshal(message, &conn)
				require.NoError(t, jsonErr)

				if conn.State == "responded" {
					close(done)
				}

				return nil
			},
		},
	)
	require.NoError(t, err)
	require.NotNil(t, op)

	// send connection request message
	id := "valid-thread-id"
	newDidDoc, err := (&didcreator.MockDIDCreator{}).Create("peer")
	require.NoError(t, err)

	request, err := json.Marshal(
		&didexsvc.Request{
			Type:  didexsvc.RequestMsgType,
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

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		require.Fail(t, "tests are not validated")
	}
}

func TestOperationEventError(t *testing.T) {
	client, err := didexchange.New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(),
		ServiceValue: &protocol.MockDIDExchangeSvc{}})
	require.NoError(t, err)

	ops := &Operation{client: client, actionCh: make(chan service.DIDCommAction)}

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

func TestHandleMessageEvent(t *testing.T) {
	storeProv := &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: make(map[string][]byte)}}
	op, err := New(&mockprovider.Provider{StorageProviderValue: storeProv,
		ServiceValue: &protocol.MockDIDExchangeSvc{}}, webhook.NewHTTPNotifier(nil))
	require.NoError(t, err)
	require.NotNil(t, op)

	e := didExEvent{}
	connRec := didexsvc.ConnectionRecord{ConnectionID: e.ConnectionID(), ThreadID: "xyz", State: "completed"}
	connBytes, err := json.Marshal(connRec)
	require.NoError(t, err)
	require.NoError(t, storeProv.Store.Put("conn_"+e.ConnectionID(), connBytes))
	err = op.handleMessageEvents(service.StateMsg{Type: service.PostState, Properties: "invalid didex prop type"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "event is not of DIDExchange event type")

	err = op.handleMessageEvents(service.StateMsg{Type: service.PostState, Properties: errors.New("err type")})
	require.Error(t, err)
	require.Contains(t, err.Error(), "service processing failed : err type")

	err = op.handleMessageEvents(service.StateMsg{Type: service.PostState, Properties: &didExEvent{}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "send connection notification failed : "+
		"connection notification webhook :")
}

func TestSendConnectionNotification(t *testing.T) {
	const (
		connID   = "id1"
		threadID = "xyz"
	)
	storeProv := &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: make(map[string][]byte)}}
	connRec := didexsvc.ConnectionRecord{ConnectionID: connID, ThreadID: threadID, State: "completed"}
	connBytes, err := json.Marshal(connRec)
	require.NoError(t, err)
	require.NoError(t, storeProv.Store.Put("conn_id1", connBytes))
	require.NoError(t, storeProv.Store.Put("conn_id1"+"completed", connBytes))
	t.Run("send notification success", func(t *testing.T) {
		op, err := New(&mockprovider.Provider{StorageProviderValue: storeProv,
			ServiceValue: &protocol.MockDIDExchangeSvc{}}, webhook.NewHTTPNotifier(nil))
		require.NoError(t, err)
		err = op.sendConnectionNotification(connID, "completed")
		require.NoError(t, err)
	})
	t.Run("send notification connection not found error", func(t *testing.T) {
		op, err := New(&mockprovider.Provider{StorageProviderValue: storeProv,
			ServiceValue: &protocol.MockDIDExchangeSvc{}}, webhook.NewHTTPNotifier(nil))
		require.NoError(t, err)
		err = op.sendConnectionNotification("id2", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "connection notification webhook : cannot fetch state from store:")
	})
	t.Run("send notification webhook error", func(t *testing.T) {
		op, err := New(&mockprovider.Provider{StorageProviderValue: storeProv,
			ServiceValue: &protocol.MockDIDExchangeSvc{}}, &mockNotifier{
			notifyFunc: func(topic string, message []byte) error {
				return errors.New("webhook error")
			},
		})
		require.NoError(t, err)
		require.NotNil(t, op)
		err = op.sendConnectionNotification(connID, "completed")
		require.Error(t, err)
		require.Contains(t, err.Error(), "connection notification webhook : webhook error")
	})
}

type mockNotifier struct {
	notifyFunc func(topic string, message []byte) error
}

func (n *mockNotifier) Notify(topic string, message []byte) error {
	return n.notifyFunc(topic, message)
}

type didExEvent struct {
}

func (e *didExEvent) ConnectionID() string {
	return "abc"
}

func (e *didExEvent) InvitationID() string {
	return "xyz"
}
