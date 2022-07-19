/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messaging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/messaging"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/mocks/webhook"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	svchttp "github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/service/http"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/generic"
	mocksvc "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/service"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// error messages.
	errMsgSvcNameRequired            = "service name is required"
	errMsgInvalidAcceptanceCrit      = "invalid acceptance criteria"
	errMsgBodyEmpty                  = "empty message body"
	errMsgDestinationMissing         = "missing message destination"
	errMsgDestSvcEndpointMissing     = "missing service endpoint in message destination"
	errMsgDestSvcEndpointKeysMissing = "missing service endpoint recipient/routing keys in message destination"
	errMsgIDEmpty                    = "empty message ID"
)

func TestOperation_GetAPIHandlers(t *testing.T) {
	t.Run("Initialize REST operation successfully and get handlers", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, svc)

		handlers := svc.GetRESTHandlers()
		require.NotEmpty(t, handlers)
	})

	t.Run("Test REST operation initialization failure", func(t *testing.T) {
		const errMsg = "sample-error"
		svc, err := New(&protocol.MockProvider{
			StoreProvider: &storage.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf(errMsg),
			},
		}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.Error(t, err)
		require.Nil(t, svc)
		require.Contains(t, err.Error(), errMsg)
		require.Contains(t, err.Error(), "failed to create messaging controller command")
	})
}

func TestOperation_RegisterService(t *testing.T) {
	t.Run("Successful Register Message Service", func(t *testing.T) {
		mhandler := msghandler.NewMockMsgServiceProvider()
		svc, err := New(&protocol.MockProvider{}, mhandler, webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, svc)

		jsonStr := []byte(`{
		"name":"json-msg-01",
    	"type": "https://didcomm.org/json/1.0/msg",
    	"purpose": ["prp-01","prp-02"]
  	}`)

		handler := lookupCreatePublicDIDHandler(t, svc, RegisterMsgService)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.Empty(t, buf)

		// verify if new service is registered
		require.NotEmpty(t, mhandler.Services())
		require.Equal(t, "json-msg-01", mhandler.Services()[0].Name())
		require.True(t, mhandler.Services()[0].Accept(
			"https://didcomm.org/json/1.0/msg",
			[]string{"prp-01", "prp-02"},
		))
	})

	t.Run("Register Message Service Input validation", func(t *testing.T) {
		tests := []struct {
			name      string
			json      string
			errorCode command.Code
			errorMsg  string
		}{
			{
				name:      "missing name test",
				json:      `{"type": "https://didcomm.org/json/1.0/msg","purpose": ["prp-01","prp-02"]}`,
				errorCode: messaging.InvalidRequestErrorCode,
				errorMsg:  errMsgSvcNameRequired,
			},
			{
				name:      "missing type test",
				json:      `{"name": "svx-001"}`,
				errorCode: messaging.InvalidRequestErrorCode,
				errorMsg:  errMsgInvalidAcceptanceCrit,
			},
			{
				name:      "message decode error",
				json:      `-----`,
				errorCode: messaging.InvalidRequestErrorCode,
				errorMsg:  "invalid character",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				svc, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
				require.NoError(t, err)
				require.NotNil(t, svc)

				handler := lookupCreatePublicDIDHandler(t, svc, RegisterMsgService)
				buf, code, err := sendRequestToHandler(handler, bytes.NewBufferString(tc.json), handler.Path())
				require.NoError(t, err)
				require.NotEmpty(t, buf)
				require.Equal(t, http.StatusBadRequest, code)
				verifyError(t, tc.errorCode, tc.errorMsg, buf.Bytes())
			})
		}
	})

	t.Run("Register Message Service failure", func(t *testing.T) {
		const errMsg = "sample-error"
		mhandler := msghandler.NewMockMsgServiceProvider()
		mhandler.RegisterErr = fmt.Errorf(errMsg)

		svc, err := New(&protocol.MockProvider{}, mhandler, webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, svc)

		jsonStr := []byte(`{
		"name":"json-msg-01",
    	"type": "https://didcomm.org/json/1.0/msg",
    	"purpose": ["prp-01","prp-02"]
  	}`)

		handler := lookupCreatePublicDIDHandler(t, svc, RegisterMsgService)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)
		require.Equal(t, http.StatusInternalServerError, code)
		verifyError(t, messaging.RegisterMsgSvcError, errMsg, buf.Bytes())
	})
}

func TestOperation_RegisterHTTPService(t *testing.T) {
	t.Run("Successful Register HTTP Message Service", func(t *testing.T) {
		mhandler := msghandler.NewMockMsgServiceProvider()
		svc, err := New(&protocol.MockProvider{}, mhandler, webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, svc)

		jsonStr := []byte(`{
		"name":"json-msg-01",
    	"purpose": ["prp-01","prp-02"]
  	}`)

		handler := lookupCreatePublicDIDHandler(t, svc, RegisterHTTPOverDIDCommService)
		buf, err := getSuccessResponseFromHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.Empty(t, buf)

		// verify if new service is registered
		require.NotEmpty(t, mhandler.Services())
		require.Equal(t, "json-msg-01", mhandler.Services()[0].Name())
		require.True(t, mhandler.Services()[0].Accept(
			svchttp.OverDIDCommMsgRequestType,
			[]string{"prp-01", "prp-02"},
		))
	})

	t.Run("Register HTTP Message Service Input validation", func(t *testing.T) {
		tests := []struct {
			name      string
			json      string
			errorCode command.Code
			errorMsg  string
		}{
			{
				name:      "missing name test",
				json:      `{"purpose": ["prp-01","prp-02"]}`,
				errorCode: messaging.InvalidRequestErrorCode,
				errorMsg:  errMsgSvcNameRequired,
			},
			{
				name:      "message decode error test",
				json:      `-----`,
				errorCode: messaging.InvalidRequestErrorCode,
				errorMsg:  "invalid character",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				svc, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
				require.NoError(t, err)
				require.NotNil(t, svc)

				handler := lookupCreatePublicDIDHandler(t, svc, RegisterHTTPOverDIDCommService)
				buf, code, err := sendRequestToHandler(handler, bytes.NewBufferString(tc.json), handler.Path())
				require.NoError(t, err)
				require.NotEmpty(t, buf)
				require.Equal(t, http.StatusBadRequest, code)
				verifyError(t, tc.errorCode, tc.errorMsg, buf.Bytes())
			})
		}
	})

	t.Run("HTTP message service registration failure", func(t *testing.T) {
		const errMsg = "sample-error"
		mhandler := msghandler.NewMockMsgServiceProvider()
		mhandler.RegisterErr = fmt.Errorf(errMsg)

		svc, err := New(&protocol.MockProvider{}, mhandler, webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, svc)

		jsonStr := []byte(`{
		"name":"json-msg-01",
    	"purpose": ["prp-01","prp-02"]
  	}`)

		handler := lookupCreatePublicDIDHandler(t, svc, RegisterHTTPOverDIDCommService)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)
		require.Equal(t, http.StatusInternalServerError, code)
		verifyError(t, messaging.RegisterMsgSvcError, errMsg, buf.Bytes())
	})
}

func TestOperation_UnregisterService(t *testing.T) {
	t.Run("Unregistering non existing message service", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, svc)

		jsonStr := []byte(`{
		"name":"json-msg-01"
  	}`)

		handler := lookupCreatePublicDIDHandler(t, svc, UnregisterMsgService)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)
		require.Equal(t, http.StatusInternalServerError, code)
		verifyError(t, messaging.UnregisterMsgSvcError, "failed to unregister", buf.Bytes())
	})

	t.Run("Unregistering message service input validation", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, svc)

		jsonStr := []byte(`{
		"name":""
  	}`)

		handler := lookupCreatePublicDIDHandler(t, svc, UnregisterMsgService)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)
		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, messaging.InvalidRequestErrorCode, errMsgSvcNameRequired, buf.Bytes())
	})

	t.Run("Unregistering message service successfully", func(t *testing.T) {
		msgRegistrar := msghandler.NewMockMsgServiceProvider()
		svc, err := New(&protocol.MockProvider{}, msgRegistrar, webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, svc)

		svcNames := []string{"svc-01", "svc-02", "svc-03", "svc-04"}
		for _, svcName := range svcNames {
			err := msgRegistrar.Register(generic.NewCustomMockMessageSvc("test", svcName))
			require.NoError(t, err)
		}

		jsonStr := `{"name":"%s"}`
		for _, svcName := range svcNames {
			handler := lookupCreatePublicDIDHandler(t, svc, UnregisterMsgService)
			buf, err := getSuccessResponseFromHandler(handler,
				bytes.NewBufferString(fmt.Sprintf(jsonStr, svcName)),
				handler.Path())
			require.NoError(t, err)
			require.Empty(t, buf)
		}
	})

	t.Run("Unregistering message service input decode failure", func(t *testing.T) {
		svc, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, svc)

		jsonStr := []byte(`{--`)

		handler := lookupCreatePublicDIDHandler(t, svc, UnregisterMsgService)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBuffer(jsonStr), handler.Path())
		require.NoError(t, err)
		require.NotEmpty(t, buf)
		require.Equal(t, http.StatusBadRequest, code)
		verifyError(t, messaging.InvalidRequestErrorCode, "invalid character", buf.Bytes())
	})
}

func TestOperation_Services(t *testing.T) {
	msgRegistrar := msghandler.NewMockMsgServiceProvider()
	svc, err := New(&protocol.MockProvider{}, msgRegistrar, webhook.NewMockWebhookNotifier())
	require.NoError(t, err)
	require.NotNil(t, svc)

	verifyResponse := func(buf *bytes.Buffer, count int) {
		response := registeredServicesResponse{}
		err = json.Unmarshal(buf.Bytes(), &response)
		require.NoError(t, err)

		require.NotEmpty(t, response)
		require.Len(t, response.Names, count)
	}

	handler := lookupCreatePublicDIDHandler(t, svc, MsgServiceList)
	buf, err := getSuccessResponseFromHandler(handler, nil, handler.Path())
	require.NoError(t, err)
	verifyResponse(buf, 0)

	testMsgSvcs := []dispatcher.MessageService{
		generic.NewCustomMockMessageSvc("type-01", "svc-name-01"),
		generic.NewCustomMockMessageSvc("type-02", "svc-name-02"),
		generic.NewCustomMockMessageSvc("type-03", "svc-name-03"),
		generic.NewCustomMockMessageSvc("type-04", "svc-name-04"),
		generic.NewCustomMockMessageSvc("type-05", "svc-name-05"),
	}
	err = msgRegistrar.Register(testMsgSvcs...)
	require.NoError(t, err)

	buf, err = getSuccessResponseFromHandler(handler, nil, handler.Path())
	require.NoError(t, err)
	verifyResponse(buf, len(testMsgSvcs))
}

func TestOperation_Send(t *testing.T) {
	t.Run("Test request param validation", func(t *testing.T) {
		tests := []struct {
			name        string
			requestJSON string
			httpErrCode int
			errorCode   command.Code
			errorMsg    string
		}{
			{
				name:        "missing all params",
				requestJSON: `{}`,
				httpErrCode: http.StatusBadRequest,
				errorCode:   messaging.InvalidRequestErrorCode,
				errorMsg:    errMsgBodyEmpty,
			},
			{
				name:        "missing message body",
				requestJSON: `{"connection_ID": "dsfds"}`,
				httpErrCode: http.StatusBadRequest,
				errorCode:   messaging.InvalidRequestErrorCode,
				errorMsg:    errMsgBodyEmpty,
			},
			{
				name:        "missing destinations",
				requestJSON: `{"message_body": {"text":"sample msg 123"}}`,
				httpErrCode: http.StatusBadRequest,
				errorCode:   messaging.InvalidRequestErrorCode,
				errorMsg:    errMsgDestinationMissing,
			},
			{
				name:        "invalid service endpoint - missing endpoint",
				requestJSON: `{"message_body": {"text":"sample msg 123"}, "service_endpoint": {}}`,
				httpErrCode: http.StatusBadRequest,
				errorCode:   messaging.InvalidRequestErrorCode,
				errorMsg:    errMsgDestSvcEndpointMissing,
			},
			{
				name:        "invalid service endpoint - missing destination keys",
				requestJSON: `{"message_body": {"text":"sample"}, "service_endpoint": {"serviceEndpoint": "sdfsdf"}}`,
				httpErrCode: http.StatusBadRequest,
				errorCode:   messaging.InvalidRequestErrorCode,
				errorMsg:    errMsgDestSvcEndpointKeysMissing,
			},
			{
				name:        "invalid input",
				requestJSON: `{"message_body": -----}`,
				httpErrCode: http.StatusBadRequest,
				errorCode:   messaging.InvalidRequestErrorCode,
				errorMsg:    "invalid character",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				svc, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
				require.NoError(t, err)
				require.NotNil(t, svc)

				handler := lookupCreatePublicDIDHandler(t, svc, SendNewMsg)
				buf, code, err := sendRequestToHandler(handler, bytes.NewBufferString(tc.requestJSON), handler.Path())
				require.NoError(t, err)
				require.NotEmpty(t, buf)
				require.Equal(t, tc.httpErrCode, code)
				verifyError(t, tc.errorCode, tc.errorMsg, buf.Bytes())
			})
		}
	})

	t.Run("Test send new message success", func(t *testing.T) {
		tests := []struct {
			name           string
			testConnection *connection.Record
			requestJSON    string
		}{
			{
				name: "send message to connection ID",
				testConnection: &connection.Record{
					ConnectionID: "sample-conn-ID-001",
					State:        "completed", MyDID: "mydid", TheirDID: "theirDID-001",
				},
				requestJSON: `{"message_body": {"text":"sample"}, "connection_id": "sample-conn-ID-001"}`,
			},
			{
				name: "send message to their DID",
				testConnection: &connection.Record{
					ConnectionID: "sample-conn-ID-001",
					State:        "completed", MyDID: "mydid", TheirDID: "theirDID-001",
				},
				requestJSON: `{"message_body": {"text":"sample"}, "their_did": "theirDID-001"}`,
			},
			{
				name: "send message to destination",
				requestJSON: `{"message_body": {"text":"sample"},"service_endpoint": {"serviceEndpoint": "sdfsdf",
			"recipientKeys":["test"]}}`,
			},
		}

		// Note: copied from store/connection/connection_lookup.go
		mockDIDTagFunc := func(dids ...string) string {
			for i, v := range dids {
				dids[i] = strings.ReplaceAll(v, ":", "$")
			}

			return strings.Join(dids, "|")
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				mockStore := &storage.MockStore{Store: make(map[string]storage.DBEntry)}
				if tc.testConnection != nil {
					connBytes, err := json.Marshal(tc.testConnection)
					require.NoError(t, err)
					require.NoError(t, mockStore.Put(fmt.Sprintf("conn_%s", tc.testConnection.ConnectionID),
						connBytes,
						spi.Tag{Name: "conn_"},
						spi.Tag{Name: "bothDIDs", Value: mockDIDTagFunc(tc.testConnection.MyDID, tc.testConnection.TheirDID)},
						spi.Tag{Name: "theirDID", Value: mockDIDTagFunc(tc.testConnection.TheirDID)},
					))
				}

				svc, err := New(&protocol.MockProvider{StoreProvider: storage.NewCustomMockStoreProvider(mockStore)},
					msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
				require.NoError(t, err)
				require.NotNil(t, svc)

				handler := lookupCreatePublicDIDHandler(t, svc, SendNewMsg)
				buf, err := getSuccessResponseFromHandler(handler, bytes.NewBufferString(tc.requestJSON), handler.Path())
				require.NoError(t, err)
				require.Contains(t, buf.String(), "{}")
			})
		}
	})

	t.Run("Test send new message failures", func(t *testing.T) {
		tests := []struct {
			name           string
			testConnection *connection.Record
			messenger      *mocksvc.MockMessenger
			kms            *mockkms.KeyManager
			vdr            *mockvdr.MockVDRegistry
			requestJSON    string
			httpErrCode    int
			errorCode      command.Code
			errorMsg       string
		}{
			{
				name:           "send message to connection ID data not found error",
				testConnection: nil,
				requestJSON:    `{"message_body": {"text":"sample"}, "connection_id": "sample-conn-ID-001"}`,
				httpErrCode:    http.StatusInternalServerError,
				errorCode:      messaging.SendMsgError,
				errorMsg:       "data not found",
			},
			{
				name: "send message to connection ID send error",
				testConnection: &connection.Record{
					ConnectionID: "sample-conn-ID-001",
					State:        "completed", MyDID: "mydid", TheirDID: "theirDID-001",
				},
				requestJSON: `{"message_body": {"text":"sample"}, "connection_id": "sample-conn-ID-001"}`,
				messenger:   &mocksvc.MockMessenger{ErrSend: fmt.Errorf("sample-err-01")},
				httpErrCode: http.StatusInternalServerError,
				errorCode:   messaging.SendMsgError,
				errorMsg:    "sample-err-01",
			},
			{
				name: "send message to their DID data not found error",
				testConnection: &connection.Record{
					ConnectionID: "sample-conn-ID-001",
					State:        "completed", MyDID: "mydid", TheirDID: "theirDID-z",
				},
				requestJSON: `{"message_body": {"text":"sample"}, "their_did": "theirDID-001"}`,
				httpErrCode: http.StatusInternalServerError,
				errorCode:   messaging.SendMsgError,
				errorMsg:    vdrapi.ErrNotFound.Error(),
			},
			{
				name: "send message to destination",
				requestJSON: `{"message_body": {"text":"sample"},"service_endpoint": {"serviceEndpoint": "sdfsdf", 
"recipientKeys":["test"]}}`,
				messenger:   &mocksvc.MockMessenger{ErrSendToDestination: fmt.Errorf("sample-err-01")},
				httpErrCode: http.StatusInternalServerError,
				errorCode:   messaging.SendMsgError,
				errorMsg:    "sample-err-01",
			},
			{
				name: "send message to destination",
				requestJSON: `{"message_body": {"text":"sample"},"service_endpoint": {"serviceEndpoint": "sdfsdf", 
"recipientKeys":["test"]}}`,
				kms:         &mockkms.KeyManager{CrAndExportPubKeyErr: fmt.Errorf("sample-kmserr-01")},
				httpErrCode: http.StatusInternalServerError,
				errorCode:   messaging.SendMsgError,
				errorMsg:    "sample-kmserr-01",
			},
			{
				name:        "failed to resolve destination from DID",
				requestJSON: `{"message_body": {"text":"sample"}, "their_did": "theirDID-001"}`,
				vdr:         &mockvdr.MockVDRegistry{ResolveErr: fmt.Errorf("sample-err-01")},
				httpErrCode: http.StatusInternalServerError,
				errorCode:   messaging.SendMsgError,
				errorMsg:    "sample-err-01",
			},
			{
				name:        "invalid message body - scenario 1",
				requestJSON: `{"message_body": "sample-input", "their_did": "theirDID-001"}`,
				vdr: &mockvdr.MockVDRegistry{
					ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
						return &did.DocResolution{DIDDocument: mockdiddoc.GetMockDIDDoc(t, false)}, nil
					},
				},
				httpErrCode: http.StatusInternalServerError,
				errorCode:   messaging.SendMsgError,
				errorMsg:    "invalid payload data format",
			},
			{
				name: "invalid message body - scenario 2",
				testConnection: &connection.Record{
					ConnectionID: "sample-conn-ID-001",
					State:        "completed", MyDID: "mydid", TheirDID: "theirDID-001",
				},
				requestJSON: `{"message_body": "sample-input", "connection_id": "sample-conn-ID-001"}`,
				httpErrCode: http.StatusInternalServerError,
				errorCode:   messaging.SendMsgError,
				errorMsg:    "invalid payload data format",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				provider := &protocol.MockProvider{}

				if tc.testConnection != nil {
					mockStore := &storage.MockStore{Store: make(map[string]storage.DBEntry)}
					connBytes, err := json.Marshal(tc.testConnection)
					require.NoError(t, err)
					require.NoError(t, mockStore.Put(fmt.Sprintf("conn_%s", tc.testConnection.ConnectionID), connBytes))
					provider.StoreProvider = storage.NewCustomMockStoreProvider(mockStore)
				}

				if tc.messenger != nil {
					provider.CustomMessenger = tc.messenger
				}

				if tc.kms != nil {
					provider.CustomKMS = tc.kms
				}

				if tc.vdr != nil {
					provider.CustomVDR = tc.vdr
				}

				svc, err := New(provider, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
				require.NoError(t, err)
				require.NotNil(t, svc)

				handler := lookupCreatePublicDIDHandler(t, svc, SendNewMsg)
				buf, code, err := sendRequestToHandler(handler, bytes.NewBufferString(tc.requestJSON), handler.Path())
				require.NoError(t, err)
				require.NotEmpty(t, buf)
				require.Equal(t, tc.httpErrCode, code)
				verifyError(t, tc.errorCode, tc.errorMsg, buf.Bytes())
			})
		}
	})
}

func TestOperation_Reply(t *testing.T) {
	t.Run("Test request param validation", func(t *testing.T) {
		tests := []struct {
			name        string
			requestJSON string
			messenger   *mocksvc.MockMessenger
			httpErrCode int
			errorCode   command.Code
			errorMsg    string
		}{
			{
				name:        "missing all params",
				requestJSON: `{}`,
				httpErrCode: http.StatusBadRequest,
				errorCode:   messaging.InvalidRequestErrorCode,
				errorMsg:    errMsgBodyEmpty,
			},
			{
				name:        "missing message body",
				requestJSON: `{"message_ID": "1234"}`,
				httpErrCode: http.StatusBadRequest,
				errorCode:   messaging.InvalidRequestErrorCode,
				errorMsg:    errMsgBodyEmpty,
			},
			{
				name:        "missing message id",
				requestJSON: `{"message_body": "sample"}`,
				httpErrCode: http.StatusBadRequest,
				errorCode:   messaging.InvalidRequestErrorCode,
				errorMsg:    errMsgIDEmpty,
			},
			{
				name:        "invalid input",
				requestJSON: `----`,
				httpErrCode: http.StatusBadRequest,
				errorCode:   messaging.InvalidRequestErrorCode,
				errorMsg:    "invalid character",
			},
			{
				name:        "invalid message format",
				requestJSON: `{"message_ID": "1234","message_body": {"msg":"Hello !!"}}`,
				messenger:   &mocksvc.MockMessenger{ErrReplyTo: fmt.Errorf("sample-err-01")},
				httpErrCode: http.StatusInternalServerError,
				errorCode:   messaging.SendMsgReplyError,
				errorMsg:    "sample-err-01",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				provider := &protocol.MockProvider{}

				if tc.messenger != nil {
					provider.CustomMessenger = tc.messenger
				}

				svc, err := New(provider, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
				require.NoError(t, err)
				require.NotNil(t, svc)

				handler := lookupCreatePublicDIDHandler(t, svc, SendReplyMsg)
				buf, code, err := sendRequestToHandler(handler, bytes.NewBufferString(tc.requestJSON), handler.Path())
				require.NoError(t, err)
				require.NotEmpty(t, buf)
				require.Equal(t, tc.httpErrCode, code)
				verifyError(t, tc.errorCode, tc.errorMsg, buf.Bytes())
			})
		}
	})

	t.Run("Test send message reply", func(t *testing.T) {
		const jsonMsg = `{"message_ID": "1234","message_body": {"msg":"hello !!"}}`
		svc, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, svc)

		handler := lookupCreatePublicDIDHandler(t, svc, SendReplyMsg)
		buf, code, err := sendRequestToHandler(handler, bytes.NewBufferString(jsonMsg), handler.Path())
		require.NoError(t, err)
		require.Contains(t, buf.String(), "{}")
		require.Equal(t, http.StatusOK, code)
	})
}

func lookupCreatePublicDIDHandler(t *testing.T, op *Operation, path string) rest.Handler {
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
