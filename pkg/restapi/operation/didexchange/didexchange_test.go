/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	didexsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockdidexchange "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol/didexchange"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/internal/mock/kms/legacykms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/internal/mock/vdri"
	resterr "github.com/hyperledger/aries-framework-go/pkg/restapi/errors"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation/didexchange/models"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/webhook"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

func TestOperation_GetAPIHandlers(t *testing.T) {
	svc, err := New(&mockprovider.Provider{
		TransientStorageProviderValue: mockstore.NewMockStoreProvider(),
		StorageProviderValue:          mockstore.NewMockStoreProvider(),
		ServiceValue:                  &mockdidexchange.MockDIDExchangeSvc{}},
		webhook.NewHTTPNotifier(nil), "", false)
	require.NoError(t, err)
	require.NotNil(t, svc)

	handlers := svc.GetRESTHandlers()
	require.NotEmpty(t, handlers)
}

func TestNew_Fail(t *testing.T) {
	svc, err := New(&mockprovider.Provider{ServiceErr: errors.New("test-error")},
		webhook.NewHTTPNotifier(nil), "", false)
	require.Error(t, err)
	require.Nil(t, svc)
}

func TestOperation_CreateInvitation(t *testing.T) {
	t.Run("Successful CreateInvitation with label", func(t *testing.T) {
		handler := getHandler(t, createInvitationPath)
		buf, err := getSuccessResponseFromHandler(handler, nil, handler.Path()+"?alias=mylabel")
		require.NoError(t, err)

		response := models.CreateInvitationResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response.Invitation)
		require.Equal(t, "endpoint", response.Invitation.ServiceEndpoint)
		require.Empty(t, response.Invitation.Label)
		require.NotEmpty(t, response.Alias)
	})

	t.Run("Successful CreateInvitation with label and public DID", func(t *testing.T) {
		const publicDID = "sample-public-did"
		handler := getHandler(t, createInvitationPath)
		buf, err := getSuccessResponseFromHandler(handler, nil, handler.Path()+"?alias=mylabel&public="+publicDID)
		require.NoError(t, err)

		response := models.CreateInvitationResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response.Invitation)
		require.Empty(t, response.Invitation.ServiceEndpoint)
		require.Empty(t, response.Invitation.Label)
		require.NotEmpty(t, response.Alias)
		require.NotEmpty(t, response.Invitation.DID)
		require.Equal(t, publicDID, response.Invitation.DID)
	})

	t.Run("Successful CreateInvitation with default params", func(t *testing.T) {
		handler := getHandler(t, createInvitationPath)
		buf, err := getSuccessResponseFromHandler(handler, nil, handler.Path())
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
}

func TestOperation_ReceiveInvitation(t *testing.T) {
	var jsonStr = []byte(`{
		"serviceEndpoint":"http://alice.agent.example.com:8081",
		"recipientKeys":["FDmegH8upiNquathbHZiGBZKwcudNfNWPeGQFBt8eNNi"],
		"@id":"a35c0ac6-4fc3-46af-a072-c1036d036057",
		"label":"agent",
		"@type":"https://didcomm.org/didexchange/1.0/invitation"}`)

	handler := getHandler(t, receiveInvitationPath)
	buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
	require.NoError(t, err)

	response := models.ReceiveInvitationResponse{}
	err = json.Unmarshal(buf.Bytes(), &response)
	require.NoError(t, err)

	// verify response
	require.NotEmpty(t, response)
	require.NotEmpty(t, response.ConnectionID)
}

func TestOperation_QueryConnectionByID(t *testing.T) {
	handler := getHandler(t, connectionsByID)
	buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer([]byte("sample-connection-id")),
		operationID+"/1234")
	require.NoError(t, err)

	response := models.QueryConnectionResponse{}
	err = json.Unmarshal(buf.Bytes(), &response)
	require.NoError(t, err)

	// verify response
	require.NotEmpty(t, response)
	require.NotEmpty(t, response.Result.ConnectionID)
}

func TestOperation_QueryConnectionByParams(t *testing.T) {
	// perform receive invitation to insert record into store
	var jsonStr = []byte(`{
		"serviceEndpoint":"http://alice.agent.example.com:8081",
		"recipientKeys":["FDmegH8upiNquathbHZiGBZKwcudNfNWPeGQFBt8eNNi"],
		"@id":"a35c0ac6-4fc3-46af-a072-c1036d036057",
		"label":"agent",
		"@type":"https://didcomm.org/didexchange/1.0/invitation"}`)

	handler := getHandler(t, receiveInvitationPath)
	_, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
	require.NoError(t, err)

	t.Run("test query connections with state filter", func(t *testing.T) {
		// perform test
		handler = getHandler(t, connections)
		buf, err := getSuccessResponseFromHandler(handler, nil,
			operationID+"?state=complete")
		require.NoError(t, err)

		response := models.QueryConnectionsResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.Results)
		for _, result := range response.Results {
			require.NotNil(t, result)
			require.NotNil(t, result.ConnectionID)
		}
	})

	t.Run("test query connections without state filter", func(t *testing.T) {
		// perform test
		handler = getHandler(t, connections)
		buf, err := getSuccessResponseFromHandler(handler, nil,
			operationID)
		require.NoError(t, err)

		response := models.QueryConnectionsResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.Results)
		for _, result := range response.Results {
			require.NotNil(t, result)
			require.NotNil(t, result.ConnectionID)
		}
	})
}

func TestOperation_ReceiveInvitationFailure(t *testing.T) {
	// Failure in service
	var jsonStr = []byte(`{
    	"@type": "https://didcomm.org/connections/1.0/invitation",
    	"@id": "4e8650d9-6cc9-491e-b00e-7bf6cb5858fc",
    	"serviceEndpoint": "http://ip10-0-46-4-blikjbs9psqg8vrg4p10-8020.direct.play-with-von.vonx.io",
    	"label": "Faber Agent",
    	"recipientKeys": [
      		"6LE8yhZB8Xffc5vFgFntE3YLrxq5JVUsoAvUQgUyktGt"
    		]
  	}`)

	handler := getHandlerWithError(t, receiveInvitationPath, errors.New("handler failed"), nil, nil)
	buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
	require.NoError(t, err)
	require.Equal(t, http.StatusInternalServerError, code)
	verifyRESTError(t, ReceiveInvitationErrorCode, buf.Bytes())

	// Failure due to invalid request body
	jsonStr = []byte("")
	handler = getHandler(t, receiveInvitationPath)
	buf, code, err = sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, code)

	verifyRESTError(t, InvalidRequestErrorCode, buf.Bytes())
}

func TestOperation_AcceptInvitation(t *testing.T) {
	t.Run("test accept invitation success", func(t *testing.T) {
		handler := getHandler(t, acceptInvitationPath)
		buf, err := getSuccessResponseFromHandler(handler, nil,
			operationID+"/1111/accept-invitation?public=sample-public-did")
		require.NoError(t, err)

		response := models.AcceptInvitationResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		require.NotEmpty(t, response)
		require.NotEmpty(t, response.ConnectionID)
	})

	t.Run("test accept invitation failures", func(t *testing.T) {
		handler := getHandlerWithError(t, acceptInvitationPath, nil, fmt.Errorf("fail it"), nil)
		buf, code, err := sendRequestToHandler(handler, nil,
			operationID+"/1111/accept-invitation?publicDID=xyz")
		require.NoError(t, err)

		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, code)
		verifyRESTError(t, AcceptInvitationErrorCode, buf.Bytes())
	})
}

func TestOperation_CreateImplicitInvitation(t *testing.T) {
	t.Run("test create implicit invitation success", func(t *testing.T) {
		handler := getHandler(t, createImplicitInvitationPath)
		buf, err := getSuccessResponseFromHandler(handler, nil,
			createImplicitInvitationPath+"?their_did=sample-public-did")
		require.NoError(t, err)

		response := models.ImplicitInvitationResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		require.NotEmpty(t, response)
		require.NotEmpty(t, response.ConnectionID)
	})

	t.Run("test create implicit invitation with DID success", func(t *testing.T) {
		handler := getHandler(t, createImplicitInvitationPath)
		buf, err := getSuccessResponseFromHandler(handler, nil,
			createImplicitInvitationPath+"?their_did=their-public-did&my_did=my-public-did")
		require.NoError(t, err)

		response := models.ImplicitInvitationResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		require.NotEmpty(t, response)
		require.NotEmpty(t, response.ConnectionID)
	})

	t.Run("test required parameters", func(t *testing.T) {
		handler := getHandler(t, createImplicitInvitationPath)
		buf, code, err := sendRequestToHandler(handler, nil,
			createImplicitInvitationPath+"?invalid=xyz")
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)

		verifyRESTError(t, InvalidRequestErrorCode, buf.Bytes())
	})

	t.Run("test handler failure", func(t *testing.T) {
		handler := getHandlerWithError(t, createImplicitInvitationPath, nil, nil, fmt.Errorf("implicit error"))
		buf, code, err := sendRequestToHandler(handler, nil,
			createImplicitInvitationPath+"?their_did=xyz")
		require.NoError(t, err)

		require.Equal(t, http.StatusInternalServerError, code)
		verifyRESTError(t, CreateImplicitInvitationErrorCode, buf.Bytes())
	})
}

func TestOperation_AcceptExchangeRequest(t *testing.T) {
	t.Run("test accept exchange request failures", func(t *testing.T) {
		handler := getHandler(t, acceptExchangeRequest)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer([]byte("test-id")),
			operationID+"/4444/accept-request?public=sample-public-did")
		require.NoError(t, err)

		response := models.AcceptExchangeResult{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.Result.ConnectionID)
	})

	t.Run("test accept exchange request failures", func(t *testing.T) {
		handler := getHandlerWithError(t, acceptExchangeRequest, nil, fmt.Errorf("fail it"), nil)
		buf, code, err := sendRequestToHandler(handler, nil,
			operationID+"/4444/accept-request?public=sample-public-did")
		require.NoError(t, err)

		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, code)
		verifyRESTError(t, AcceptExchangeRequestErrorCode, buf.Bytes())
	})
}

func TestOperation_RemoveConnection(t *testing.T) {
	handler := getHandler(t, removeConnection)
	buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer([]byte("test-id")),
		operationID+"/5555/remove")
	require.NoError(t, err)
	require.Empty(t, buf.Bytes())
}

func TestOperation_WriteResponse(t *testing.T) {
	svc, err := New(&mockprovider.Provider{
		TransientStorageProviderValue: mockstore.NewMockStoreProvider(),
		StorageProviderValue:          mockstore.NewMockStoreProvider(),
		ServiceValue:                  &mockdidexchange.MockDIDExchangeSvc{}},
		webhook.NewHTTPNotifier(nil), "", false)
	require.NoError(t, err)
	require.NotNil(t, svc)
	svc.writeResponse(&httptest.ResponseRecorder{}, &models.QueryConnectionResponse{})
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

func getHandler(t *testing.T, lookup string) operation.Handler {
	return getHandlerWithError(t, lookup, nil, nil, nil)
}

func getHandlerWithError(t *testing.T, lookup string, handleErr, acceptErr, implicitErr error) operation.Handler {
	transientStore := mockstore.MockStore{Store: make(map[string][]byte)}
	store := mockstore.MockStore{Store: make(map[string][]byte)}
	connRec := &connection.Record{State: "complete", ConnectionID: "1234", ThreadID: "th1234"}

	connBytes, err := json.Marshal(connRec)
	require.NoError(t, err)
	require.NoError(t, store.Put("conn_1234", connBytes))

	h := crypto.SHA256.New()
	hash := h.Sum([]byte(connRec.ConnectionID))
	key := fmt.Sprintf("%x", hash)

	require.NoError(t, store.Put("my_"+key, []byte(connRec.ConnectionID)))

	svc, err := New(&mockprovider.Provider{
		ServiceValue: &mockdidexchange.MockDIDExchangeSvc{
			ProtocolName: "mockProtocolSvc",
			HandleFunc: func(msg *service.DIDCommMsg) (string, error) {
				return uuid.New().String(), handleErr
			},
			AcceptError:           acceptErr,
			ImplicitInvitationErr: implicitErr,
		},
		KMSValue:                      &mockkms.CloseableKMS{CreateEncryptionKeyValue: "sample-key"},
		InboundEndpointValue:          "endpoint",
		TransientStorageProviderValue: &mockstore.MockStoreProvider{Store: &transientStore},
		StorageProviderValue:          &mockstore.MockStoreProvider{Store: &store}},
		webhook.NewHTTPNotifier(nil),
		"", true,
	)
	require.NoError(t, err)
	require.NotNil(t, svc)

	return handlerLookup(t, svc, lookup)
}

func handlerLookup(t *testing.T, op *Operation, lookup string) operation.Handler {
	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == lookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

func TestAcceptExchangeRequest(t *testing.T) {
	transientStore := mockstore.NewMockStoreProvider()
	store := mockstore.NewMockStoreProvider()
	didExSvc, err := didexsvc.New(
		&protocol.MockProvider{TransientStoreProvider: transientStore, StoreProvider: store})

	require.NoError(t, err)

	done := make(chan struct{})
	connID := make(chan string)

	// create the client
	op, err := New(&mockprovider.Provider{
		TransientStorageProviderValue: transientStore,
		StorageProviderValue:          store,
		ServiceValue:                  didExSvc,
		KMSValue:                      &mockkms.CloseableKMS{CreateEncryptionKeyValue: "sample-key"}},
		&mockNotifier{
			notifyFunc: func(topic string, message []byte) error {
				require.Equal(t, connectionsWebhookTopic, topic)

				conn := ConnectionMsg{}
				jsonErr := json.Unmarshal(message, &conn)
				require.NoError(t, jsonErr)

				if conn.State == "requested" {
					connID <- conn.ConnectionID
				}

				if conn.State == "responded" {
					close(done)
				}

				return nil
			},
		},
		"", false,
	)
	require.NoError(t, err)
	require.NotNil(t, op)

	// send connection request message
	id := "valid-thread-id"
	newDidDoc, err := (&mockvdri.MockVDRIRegistry{}).Create("peer")
	require.NoError(t, err)

	invitation, err := op.client.CreateInvitation("test")
	require.NoError(t, err)

	request, err := json.Marshal(
		&didexsvc.Request{
			Type:  didexsvc.RequestMsgType,
			ID:    id,
			Label: "test",
			Thread: &decorator.Thread{
				PID: invitation.ID,
			},
			Connection: &didexsvc.Connection{
				DID:    newDidDoc.ID,
				DIDDoc: newDidDoc,
			},
		},
	)
	require.NoError(t, err)

	msg, err := service.NewDIDCommMsg(request)
	require.NoError(t, err)

	_, err = didExSvc.HandleInbound(msg, "", "")
	require.NoError(t, err)

	cid := <-connID

	buf, err := getSuccessResponseFromHandler(handlerLookup(t, op, acceptExchangeRequest), bytes.NewBuffer([]byte("")),
		operationID+"/"+cid+"/accept-request")
	require.NoError(t, err)

	response := models.AcceptExchangeResult{}
	err = json.Unmarshal(buf.Bytes(), &response)
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		require.Fail(t, "tests are not validated")
	}
}

func TestAcceptInvitation(t *testing.T) {
	store := mockstore.NewMockStoreProvider()
	didExSvc, err := didexsvc.New(&protocol.MockProvider{TransientStoreProvider: store})

	require.NoError(t, err)

	done := make(chan struct{})
	connID := make(chan string)

	// create the client
	op, err := New(&mockprovider.Provider{
		TransientStorageProviderValue: store,
		StorageProviderValue:          mockstore.NewMockStoreProvider(),
		ServiceValue:                  didExSvc},
		&mockNotifier{
			notifyFunc: func(topic string, message []byte) error {
				require.Equal(t, connectionsWebhookTopic, topic)
				conn := ConnectionMsg{}
				jsonErr := json.Unmarshal(message, &conn)
				require.NoError(t, jsonErr)

				if conn.State == "invited" {
					connID <- conn.ConnectionID
				}

				if conn.State == "requested" {
					close(done)
				}

				return nil
			},
		},
		"", false,
	)
	require.NoError(t, err)
	require.NotNil(t, op)

	pubKey, _ := generateKeyPair()
	// send connection invitation message
	invitation, err := json.Marshal(
		&didexsvc.Invitation{
			Type:          didexsvc.InvitationMsgType,
			ID:            "abc",
			Label:         "test",
			RecipientKeys: []string{pubKey},
		},
	)
	require.NoError(t, err)

	msg, err := service.NewDIDCommMsg(invitation)
	require.NoError(t, err)

	_, err = didExSvc.HandleInbound(msg, "", "")
	require.NoError(t, err)

	var cid string
	select {
	case cid = <-connID:
	case <-time.After(5 * time.Second):
		require.Fail(t, "tests are not validated")
	}

	buf, err := getSuccessResponseFromHandler(handlerLookup(t, op, acceptInvitationPath), bytes.NewBuffer([]byte("")),
		operationID+"/"+cid+"/accept-invitation")
	require.NoError(t, err)

	response := models.AcceptExchangeResult{}
	err = json.Unmarshal(buf.Bytes(), &response)
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		require.Fail(t, "tests are not validated")
	}
}

func TestOperationEventError(t *testing.T) {
	const errMsg = "channel is already registered for the action event"

	t.Run("message event registration failed", func(t *testing.T) {
		client, err := didexchange.New(&mockprovider.Provider{
			TransientStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:          mockstore.NewMockStoreProvider(),
			ServiceValue: &mockdidexchange.MockDIDExchangeSvc{
				RegisterMsgEventErr: errors.New(errMsg),
			}})

		require.NoError(t, err)
		ops := &Operation{client: client, msgCh: make(chan service.StateMsg)}
		err = ops.startClientEventListener()
		require.Error(t, err)
		require.Contains(t, err.Error(), "didexchange message event registration failed: "+errMsg)
	})
}

func TestHandleMessageEvent(t *testing.T) {
	storeProv := &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: make(map[string][]byte)}}
	op, err := New(&mockprovider.Provider{
		TransientStorageProviderValue: storeProv,
		StorageProviderValue: &mockstore.MockStoreProvider{
			Store: &mockstore.MockStore{Store: make(map[string][]byte)}},
		ServiceValue: &mockdidexchange.MockDIDExchangeSvc{}},
		webhook.NewHTTPNotifier(nil), "", false)
	require.NoError(t, err)
	require.NotNil(t, op)

	e := didExEvent{}
	connRec := connection.Record{ConnectionID: e.ConnectionID(), ThreadID: "xyz", State: "completed"}
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
	connRec := connection.Record{ConnectionID: connID, ThreadID: threadID, State: "completed"}
	connBytes, err := json.Marshal(connRec)
	require.NoError(t, err)
	require.NoError(t, storeProv.Store.Put("conn_id1", connBytes))
	require.NoError(t, storeProv.Store.Put("connstate_id1"+"completed", connBytes))

	t.Run("send notification success", func(t *testing.T) {
		const testState = "completed"
		store := &mockstore.MockStore{Store: make(map[string][]byte)}
		connRec := &connection.Record{State: testState, ConnectionID: connID, ThreadID: "th1234"}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		require.NoError(t, store.Put(stateKey(connID, testState), connBytes))

		op, err := New(&mockprovider.Provider{
			TransientStorageProviderValue: &mockstore.MockStoreProvider{Store: store},
			StorageProviderValue:          &mockstore.MockStoreProvider{Store: store},
			ServiceValue:                  &mockdidexchange.MockDIDExchangeSvc{}},
			webhook.NewHTTPNotifier(nil), "", false)
		require.NoError(t, err)
		err = op.sendConnectionNotification(connID, "completed")
		require.NoError(t, err)
	})
	t.Run("send notification connection not found error", func(t *testing.T) {
		op, err := New(&mockprovider.Provider{
			TransientStorageProviderValue: storeProv,
			StorageProviderValue: &mockstore.MockStoreProvider{
				Store: &mockstore.MockStore{Store: make(map[string][]byte)}},
			ServiceValue: &mockdidexchange.MockDIDExchangeSvc{}},
			webhook.NewHTTPNotifier(nil), "", false)
		require.NoError(t, err)
		err = op.sendConnectionNotification("id2", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "connection notification webhook : cannot fetch state from store:")
	})
	t.Run("send notification webhook error", func(t *testing.T) {
		const testState = "completed"
		store := &mockstore.MockStore{Store: make(map[string][]byte)}
		connRec := &connection.Record{State: testState, ConnectionID: connID, ThreadID: "th1234"}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		require.NoError(t, store.Put(stateKey(connID, testState), connBytes))

		op, err := New(&mockprovider.Provider{
			TransientStorageProviderValue: &mockstore.MockStoreProvider{Store: store},
			StorageProviderValue:          &mockstore.MockStoreProvider{Store: store},
			ServiceValue:                  &mockdidexchange.MockDIDExchangeSvc{}},
			&mockNotifier{notifyFunc: func(topic string, message []byte) error {
				return errors.New("webhook error")
			}},
			"", false)
		require.NoError(t, err)
		require.NotNil(t, op)
		err = op.sendConnectionNotification(connID, testState)
		require.Error(t, err)
		require.Contains(t, err.Error(), "connection notification webhook : webhook error")
	})
}

func verifyRESTError(t *testing.T, code resterr.Code, data []byte) {
	// Parser generic error response
	errResponse := struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{}
	err := json.Unmarshal(data, &errResponse)
	require.NoError(t, err)

	// verify response
	require.EqualValues(t, code, errResponse.Code)
	require.NotEmpty(t, errResponse.Message)
}

func stateKey(connID, state string) string {
	return fmt.Sprintf("connstate_%s_%s", connID, state)
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
func generateKeyPair() (string, []byte) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return base58.Encode(pubKey[:]), privKey
}
