/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package legacyconnection

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

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/legacyconnection"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	"github.com/hyperledger/aries-framework-go/pkg/controller/webnotifier"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	legacyConnSvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/legacyconnection"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	mocklegacyconn "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/legacyconnection"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
)

func TestOperation_GetAPIHandlers(t *testing.T) {
	svc, err := New(&mockprovider.Provider{
		ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
		StorageProviderValue:              mockstore.NewMockStoreProvider(),
		ServiceMap: map[string]interface{}{
			legacyConnSvc.LegacyConnection: &mocklegacyconn.MockLegacyConnectionSvc{},
			mediator.Coordination:          &mockroute.MockMediatorSvc{},
		},
	},
		webnotifier.NewHTTPNotifier(nil), "", false)
	require.NoError(t, err)
	require.NotNil(t, svc)

	handlers := svc.GetRESTHandlers()
	require.NotEmpty(t, handlers)
}

func TestNew_Fail(t *testing.T) {
	svc, err := New(&mockprovider.Provider{ServiceErr: errors.New("test-error")},
		webnotifier.NewHTTPNotifier(nil), "", false)
	require.Error(t, err)
	require.Nil(t, svc)
}

func TestOperation_CreateInvitation(t *testing.T) {
	t.Run("Successful CreateInvitation with label", func(t *testing.T) {
		handler := getHandler(t, CreateInvitationPath)
		buf, err := getSuccessResponseFromHandler(handler, nil, handler.Path()+"?alias=mylabel")
		require.NoError(t, err)

		response := legacyconnection.CreateInvitationResponse{}
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
		handler := getHandler(t, CreateInvitationPath)
		buf, err := getSuccessResponseFromHandler(handler, nil, handler.Path()+"?alias=mylabel&public="+publicDID)
		require.NoError(t, err)

		response := legacyconnection.CreateInvitationResponse{}
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
		handler := getHandler(t, CreateInvitationPath)
		buf, err := getSuccessResponseFromHandler(handler, nil, handler.Path())
		require.NoError(t, err)

		response := legacyconnection.CreateInvitationResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response.Invitation)
		require.Equal(t, "endpoint", response.Invitation.ServiceEndpoint)
		require.Empty(t, response.Invitation.Label)
		require.Empty(t, response.Alias)
	})

	t.Run("CreateInvitation failure", func(t *testing.T) {
		const errMsg = "sample-err-01"
		handler := getHandlerWithError(t, CreateInvitationPath, &fails{storePutErr: fmt.Errorf(errMsg)})

		buf, code, err := sendRequestToHandler(handler, nil, handler.Path())
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, code)
		verifyRESTError(t, legacyconnection.CreateInvitationErrorCode, buf.Bytes())
	})
}

func TestOperation_ReceiveInvitation(t *testing.T) {
	jsonStr := []byte(`{
		"serviceEndpoint":"http://alice.agent.example.com:8081",
		"recipientKeys":["FDmegH8upiNquathbHZiGBZKwcudNfNWPeGQFBt8eNNi"],
		"@id":"a35c0ac6-4fc3-46af-a072-c1036d036057",
		"label":"agent",
		"@type":"https://didcomm.org/connections/1.0/invitation"}`)

	handler := getHandler(t, ReceiveInvitationPath)
	buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
	require.NoError(t, err)

	response := legacyconnection.ReceiveInvitationResponse{}
	err = json.Unmarshal(buf.Bytes(), &response)
	require.NoError(t, err)

	// verify response
	require.NotEmpty(t, response)
	require.NotEmpty(t, response.ConnectionID)
}

func TestOperation_QueryConnectionByID(t *testing.T) {
	t.Run("connectionsByID success", func(t *testing.T) {
		handler := getHandler(t, ConnectionsByID)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer([]byte("sample-connection-id")),
			OperationID+"/1234")
		require.NoError(t, err)

		response := legacyconnection.QueryConnectionResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.Result.ConnectionID)
	})

	t.Run("connectionsByID failure", func(t *testing.T) {
		const errMsg = "sample-err-01"
		handler := getHandlerWithError(t, ConnectionsByID, &fails{storeGetErr: fmt.Errorf(errMsg)})

		buf, code, err := sendRequestToHandler(handler, nil, handler.Path())
		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, code)
		verifyRESTError(t, legacyconnection.QueryConnectionsErrorCode, buf.Bytes())
	})
}

func TestOperation_QueryConnectionByParams(t *testing.T) {
	// perform receive invitation to insert record into store
	jsonStr := []byte(`{
		"serviceEndpoint":"http://alice.agent.example.com:8081",
		"recipientKeys":["FDmegH8upiNquathbHZiGBZKwcudNfNWPeGQFBt8eNNi"],
		"@id":"a35c0ac6-4fc3-46af-a072-c1036d036057",
		"label":"agent",
		"@type":"https://didcomm.org/connections/1.0/invitation"}`)

	handler := getHandler(t, ReceiveInvitationPath)
	_, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
	require.NoError(t, err)

	t.Run("test query connections with state filter", func(t *testing.T) {
		// perform test
		handler = getHandler(t, Connections)
		buf, err := getSuccessResponseFromHandler(handler, nil,
			OperationID+"?state=complete")
		require.NoError(t, err)

		response := legacyconnection.QueryConnectionsResponse{}
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
		handler = getHandler(t, Connections)
		buf, err := getSuccessResponseFromHandler(handler, nil,
			OperationID)
		require.NoError(t, err)

		response := legacyconnection.QueryConnectionsResponse{}
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
	jsonStr := []byte(`{
    	"@type": "https://didcomm.org/connections/1.0/invitation",
    	"@id": "4e8650d9-6cc9-491e-b00e-7bf6cb5858fc",
    	"serviceEndpoint": "http://ip10-0-46-4-blikjbs9psqg8vrg4p10-8020.direct.play-with-von.vonx.io",
    	"label": "Faber Agent",
    	"recipientKeys": [
      		"6LE8yhZB8Xffc5vFgFntE3YLrxq5JVUsoAvUQgUyktGt"
    		]
  	}`)

	handler := getHandlerWithError(t, ReceiveInvitationPath, &fails{handleErr: fmt.Errorf("handle failed")})
	buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
	require.NoError(t, err)
	require.Equal(t, http.StatusInternalServerError, code)
	verifyRESTError(t, legacyconnection.ReceiveInvitationErrorCode, buf.Bytes())

	// Failure due to invalid request body
	jsonStr = []byte("")
	handler = getHandler(t, ReceiveInvitationPath)
	buf, code, err = sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, code)

	verifyRESTError(t, legacyconnection.InvalidRequestErrorCode, buf.Bytes())
}

func TestOperation_AcceptInvitation(t *testing.T) {
	t.Run("test accept invitation success", func(t *testing.T) {
		handler := getHandler(t, AcceptInvitationPath)
		buf, err := getSuccessResponseFromHandler(handler, nil,
			OperationID+"/1111/accept-invitation?public=sample-public-did")
		require.NoError(t, err)

		response := legacyconnection.AcceptInvitationResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		require.NotEmpty(t, response)
		require.NotEmpty(t, response.ConnectionID)
	})

	t.Run("test accept invitation failures", func(t *testing.T) {
		handler := getHandlerWithError(t, AcceptInvitationPath, &fails{acceptErr: fmt.Errorf("fail it")})
		buf, code, err := sendRequestToHandler(handler, nil,
			OperationID+"/1111/accept-invitation?publicDID=xyz")
		require.NoError(t, err)

		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, code)
		verifyRESTError(t, legacyconnection.AcceptInvitationErrorCode, buf.Bytes())
	})
}

func TestOperation_CreateImplicitInvitation(t *testing.T) {
	t.Run("test create implicit invitation success", func(t *testing.T) {
		handler := getHandler(t, CreateImplicitInvitationPath)
		buf, err := getSuccessResponseFromHandler(handler, nil,
			CreateImplicitInvitationPath+"?their_did=sample-public-did")
		require.NoError(t, err)

		response := legacyconnection.ImplicitInvitationResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		require.NotEmpty(t, response)
		require.NotEmpty(t, response.ConnectionID)
	})

	t.Run("test create implicit invitation with DID success", func(t *testing.T) {
		handler := getHandler(t, CreateImplicitInvitationPath)
		buf, err := getSuccessResponseFromHandler(handler, nil,
			CreateImplicitInvitationPath+"?their_did=their-public-did&my_did=my-public-did")
		require.NoError(t, err)

		response := legacyconnection.ImplicitInvitationResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		require.NotEmpty(t, response)
		require.NotEmpty(t, response.ConnectionID)
	})

	t.Run("test required parameters", func(t *testing.T) {
		handler := getHandler(t, CreateImplicitInvitationPath)
		buf, code, err := sendRequestToHandler(handler, nil,
			CreateImplicitInvitationPath+"?invalid=xyz")
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, code)

		verifyRESTError(t, legacyconnection.InvalidRequestErrorCode, buf.Bytes())
	})

	t.Run("test handler failure", func(t *testing.T) {
		handler := getHandlerWithError(t, CreateImplicitInvitationPath, &fails{implicitErr: fmt.Errorf("implicit error")})
		buf, code, err := sendRequestToHandler(handler, nil,
			CreateImplicitInvitationPath+"?their_did=xyz")
		require.NoError(t, err)

		require.Equal(t, http.StatusInternalServerError, code)
		verifyRESTError(t, legacyconnection.CreateImplicitInvitationErrorCode, buf.Bytes())
	})
}

func TestOperation_AcceptConnectionRequest(t *testing.T) {
	t.Run("test accept connection request failures", func(t *testing.T) {
		handler := getHandler(t, AcceptConnectionRequest)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer([]byte("test-id")),
			OperationID+"/4444/accept-request?public=sample-public-did")
		require.NoError(t, err)

		response := legacyconnection.ConnectionResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.ConnectionID)
	})

	t.Run("test accept connection request failures", func(t *testing.T) {
		handler := getHandlerWithError(t, AcceptConnectionRequest, &fails{acceptErr: fmt.Errorf("fail it")})
		buf, code, err := sendRequestToHandler(handler, nil,
			OperationID+"/4444/accept-request?public=sample-public-did")
		require.NoError(t, err)

		require.NoError(t, err)
		require.Equal(t, http.StatusInternalServerError, code)
		verifyRESTError(t, legacyconnection.AcceptConnectionRequestErrorCode, buf.Bytes())
	})
}

func TestOperation_CreateConnection(t *testing.T) {
	t.Run("test create connection - success", func(t *testing.T) {
		myDID := newPeerDID(t)
		theirDID := newPeerDID(t)
		request, err := json.Marshal(&legacyconnection.CreateConnectionRequest{
			MyDID: myDID.ID,
			TheirDID: legacyconnection.DIDDocument{
				ID:       theirDID.ID,
				Contents: marshalDoc(t, theirDID),
			},
		})
		require.NoError(t, err)
		handler := getHandler(t, CreateConnection)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(request),
			CreateConnection)
		require.NoError(t, err)

		response := &legacyconnection.ConnectionIDArg{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.ID)
	})
}

func TestOperation_RemoveConnection(t *testing.T) {
	t.Run("test remove connection success", func(t *testing.T) {
		handler := getHandler(t, RemoveConnection)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer([]byte("test-id")),
			OperationID+"/1234/remove")
		require.NoError(t, err)
		require.Empty(t, buf.Bytes())
	})
}

func TestGetIDFromRequest(t *testing.T) {
	id, found := getIDFromRequest(httptest.NewRecorder(), &http.Request{})
	require.False(t, found)
	require.Empty(t, id)
}

func TestEmptyID(t *testing.T) {
	const response = `{"code":16000,"message":"empty connection ID"}`

	prov := &mockprovider.Provider{
		ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
		StorageProviderValue:              mockstore.NewMockStoreProvider(),
		ServiceMap: map[string]interface{}{
			legacyConnSvc.LegacyConnection: &mocklegacyconn.MockLegacyConnectionSvc{},
			mediator.Coordination:          &mockroute.MockMediatorSvc{},
		},
		KMSValue:             &mockkms.KeyManager{},
		ServiceEndpointValue: "endppint",
	}

	op, err := New(prov, webnotifier.NewHTTPNotifier(nil), "", false)
	require.NoError(t, err)
	require.NotNil(t, op)

	restHandlers := []http.HandlerFunc{
		op.AcceptInvitation, op.AcceptConnectionRequest, op.QueryConnectionByID, op.RemoveConnection,
	}
	for _, handler := range restHandlers {
		rw := httptest.NewRecorder()
		handler(rw, &http.Request{})
		require.Contains(t, rw.Body.String(), response)
	}
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

func getHandler(t *testing.T, lookup string) rest.Handler {
	t.Helper()

	return getHandlerWithError(t, lookup, &fails{})
}

type fails struct {
	handleErr, acceptErr, implicitErr, storePutErr, storeGetErr error
}

func getHandlerWithError(t *testing.T, lookup string, f *fails) rest.Handler {
	t.Helper()

	protocolStateStore := mockstore.MockStore{Store: make(map[string]mockstore.DBEntry)}
	store := mockstore.MockStore{Store: make(map[string]mockstore.DBEntry)}
	connRec := &connection.Record{State: "complete", ConnectionID: "1234", ThreadID: "th1234"}

	connBytes, err := json.Marshal(connRec)
	require.NoError(t, err)
	require.NoError(t, store.Put("conn_1234", connBytes, spi.Tag{Name: "conn_"}))

	h := crypto.SHA256.New()
	hash := h.Sum([]byte(connRec.ConnectionID))
	key := fmt.Sprintf("%x", hash)

	require.NoError(t, store.Put("my_"+key, []byte(connRec.ConnectionID)))

	if f.storePutErr != nil {
		store.ErrPut = f.storePutErr
		store.ErrGet = f.storeGetErr
	}

	ed25519KH, err := mockkms.CreateMockED25519KeyHandle()
	require.NoError(t, err)

	svc, err := New(&mockprovider.Provider{
		ServiceMap: map[string]interface{}{
			legacyConnSvc.LegacyConnection: &mocklegacyconn.MockLegacyConnectionSvc{
				ProtocolName: "mockProtocolSvc",
				HandleFunc: func(msg service.DIDCommMsg) (string, error) {
					return uuid.New().String(), f.handleErr
				},
				AcceptError:           f.acceptErr,
				ImplicitInvitationErr: f.implicitErr,
			},
			mediator.Coordination: &mockroute.MockMediatorSvc{},
		},
		KMSValue:                          &mockkms.KeyManager{CreateKeyValue: ed25519KH},
		ServiceEndpointValue:              "endpoint",
		ProtocolStateStorageProviderValue: &mockstore.MockStoreProvider{Store: &protocolStateStore},
		StorageProviderValue:              &mockstore.MockStoreProvider{Store: &store},
	},
		webnotifier.NewHTTPNotifier(nil),
		"", true,
	)
	require.NoError(t, err)
	require.NotNil(t, svc)

	return handlerLookup(t, svc, lookup)
}

func handlerLookup(t *testing.T, op *Operation, lookup string) rest.Handler {
	t.Helper()

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

func verifyRESTError(t *testing.T, code command.Code, data []byte) {
	t.Helper()

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

func newPeerDID(t *testing.T) *did.Doc {
	t.Helper()

	a, err := aries.New(
		aries.WithStoreProvider(mem.NewProvider()),
		aries.WithProtocolStateStoreProvider(mem.NewProvider()),
	)
	require.NoError(t, err)

	ctx, err := a.Context()
	require.NoError(t, err)

	d, err := ctx.VDRegistry().Create(
		peer.DIDMethod, &did.Doc{Service: []did.Service{{
			Type:            vdr.DIDCommServiceType,
			ServiceEndpoint: model.NewDIDCommV1Endpoint("http://agent.example.com/didcomm"),
		}}, VerificationMethod: []did.VerificationMethod{getSigningKey()}},
	)
	require.NoError(t, err)

	return d.DIDDocument
}

func getSigningKey() did.VerificationMethod {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return did.VerificationMethod{Value: pub[:], Type: "Ed25519VerificationKey2018"}
}

func marshalDoc(t *testing.T, d *did.Doc) []byte {
	t.Helper()

	bits, err := d.JSONBytes()
	require.NoError(t, err)

	return bits
}
