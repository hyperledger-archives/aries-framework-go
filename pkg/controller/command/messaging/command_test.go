/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messaging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/mocks/webhook"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/service/http"
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

func TestNew(t *testing.T) {
	t.Run("Test create new command success", func(t *testing.T) {
		cmd, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handlers := cmd.GetHandlers()
		require.NotEmpty(t, handlers)
	})

	t.Run("Test create new command success failure", func(t *testing.T) {
		const errMsg = "sample-error"
		cmd, err := New(&protocol.MockProvider{
			StoreProvider: &storage.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf(errMsg),
			},
		}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.Error(t, err)
		require.Nil(t, cmd)
		require.Contains(t, err.Error(), errMsg)
	})
}

func TestCommand_RegisterService(t *testing.T) {
	t.Run("Successful Register Message Service", func(t *testing.T) {
		msgRegistrar := msghandler.NewMockMsgServiceProvider()
		cmd, err := New(&protocol.MockProvider{}, msgRegistrar, webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, cmd)

		jsonStr := `{
		"name":"json-msg-01",
    	"type": "https://didcomm.org/json/1.0/msg",
    	"purpose": ["prp-01","prp-02"]
  	}`

		var b bytes.Buffer
		cmdErr := cmd.RegisterService(&b, bytes.NewBufferString(jsonStr))
		require.NoError(t, cmdErr)
		require.Empty(t, b.String())

		// verify if new service is registered
		require.NotEmpty(t, msgRegistrar.Services())
		require.Equal(t, "json-msg-01", msgRegistrar.Services()[0].Name())
		require.True(t, msgRegistrar.Services()[0].Accept(
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
				errorCode: InvalidRequestErrorCode,
				errorMsg:  errMsgSvcNameRequired,
			},
			{
				name:      "missing type test",
				json:      `{"name": "svx-001"}`,
				errorCode: InvalidRequestErrorCode,
				errorMsg:  errMsgInvalidAcceptanceCrit,
			},
			{
				name:      "message decode error",
				json:      `-----`,
				errorCode: InvalidRequestErrorCode,
				errorMsg:  "invalid character",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				cmd, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
				require.NoError(t, err)
				require.NotNil(t, cmd)

				var b bytes.Buffer
				cmdErr := cmd.RegisterService(&b, bytes.NewBufferString(tc.json))
				require.Error(t, cmdErr)
				require.Empty(t, b.String())
				require.Equal(t, cmdErr.Type(), command.ValidationError)
				require.Equal(t, cmdErr.Code(), tc.errorCode)
				require.Contains(t, cmdErr.Error(), tc.errorMsg)
			})
		}
	})

	t.Run("Register Message Service failure", func(t *testing.T) {
		const errMsg = "sample-error"
		mhandler := msghandler.NewMockMsgServiceProvider()
		mhandler.RegisterErr = fmt.Errorf(errMsg)

		cmd, err := New(&protocol.MockProvider{}, mhandler, webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, cmd)

		jsonStr := `{
			"name":"json-msg-01",
	    	"type": "https://didcomm.org/json/1.0/msg",
	    	"purpose": ["prp-01","prp-02"]
	  	}`

		var b bytes.Buffer
		cmdErr := cmd.RegisterService(&b, bytes.NewBufferString(jsonStr))
		require.Error(t, cmdErr)
		require.Empty(t, b.String())
		require.Equal(t, cmdErr.Type(), command.ExecuteError)
		require.Equal(t, cmdErr.Code(), RegisterMsgSvcError)
		require.Equal(t, cmdErr.Error(), errMsg)
	})
}

func TestCommand_RegisterHTTPService(t *testing.T) {
	t.Run("Successful Register HTTP Message Service", func(t *testing.T) {
		msgRegistrar := msghandler.NewMockMsgServiceProvider()
		cmd, err := New(&protocol.MockProvider{}, msgRegistrar, webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, cmd)

		jsonStr := `{
			"name":"json-msg-01",
	    	"purpose": ["prp-01","prp-02"]
	  	}`

		var b bytes.Buffer
		cmdErr := cmd.RegisterHTTPService(&b, bytes.NewBufferString(jsonStr))
		require.NoError(t, cmdErr)

		// verify if new service is registered
		require.NotEmpty(t, msgRegistrar.Services())
		require.Equal(t, "json-msg-01", msgRegistrar.Services()[0].Name())
		require.True(t, msgRegistrar.Services()[0].Accept(
			http.OverDIDCommMsgRequestType,
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
				errorCode: InvalidRequestErrorCode,
				errorMsg:  errMsgSvcNameRequired,
			},
			{
				name:      "message decode error test",
				json:      `-----`,
				errorCode: InvalidRequestErrorCode,
				errorMsg:  "invalid character",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				cmd, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
				require.NoError(t, err)
				require.NotNil(t, cmd)

				var b bytes.Buffer
				cmdErr := cmd.RegisterHTTPService(&b, bytes.NewBufferString(tc.json))
				require.Error(t, cmdErr)
				require.Empty(t, b.String())
				require.Equal(t, cmdErr.Type(), command.ValidationError)
				require.Equal(t, cmdErr.Code(), tc.errorCode)
				require.Contains(t, cmdErr.Error(), tc.errorMsg)
			})
		}
	})

	t.Run("HTTP message service registration failure", func(t *testing.T) {
		const errMsg = "sample-error"
		msgRegistrar := msghandler.NewMockMsgServiceProvider()
		msgRegistrar.RegisterErr = fmt.Errorf(errMsg)

		cmd, err := New(&protocol.MockProvider{}, msgRegistrar, webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, cmd)

		jsonStr := `{
			"name":"json-msg-01",
	    	"purpose": ["prp-01","prp-02"]
	  	}`

		var b bytes.Buffer
		cmdErr := cmd.RegisterHTTPService(&b, bytes.NewBufferString(jsonStr))
		require.Error(t, cmdErr)
		require.Empty(t, b.String())
		require.Equal(t, cmdErr.Type(), command.ExecuteError)
		require.Equal(t, cmdErr.Code(), RegisterMsgSvcError)
		require.Contains(t, cmdErr.Error(), errMsg)
	})
}

func TestCommand_UnregisterService(t *testing.T) {
	t.Run("Unregistering non existing message service", func(t *testing.T) {
		cmd, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, cmd)

		jsonStr := `{"name":"json-msg-01"}`

		var b bytes.Buffer
		cmdErr := cmd.UnregisterService(&b, bytes.NewBufferString(jsonStr))
		require.Error(t, cmdErr)
		require.Empty(t, b.String())
		require.Equal(t, cmdErr.Type(), command.ExecuteError)
		require.Equal(t, cmdErr.Code(), UnregisterMsgSvcError)
		require.Contains(t, cmdErr.Error(), "failed to unregister")
	})

	t.Run("Unregistering message service input validation", func(t *testing.T) {
		cmd, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.UnregisterService(&b, bytes.NewBufferString(`{"name":""}`))
		require.Error(t, cmdErr)
		require.Empty(t, b.String())
		require.Equal(t, cmdErr.Type(), command.ValidationError)
		require.Equal(t, cmdErr.Code(), InvalidRequestErrorCode)
		require.Contains(t, cmdErr.Error(), errMsgSvcNameRequired)
	})

	t.Run("Unregistering message service successfully", func(t *testing.T) {
		msgRegistrar := msghandler.NewMockMsgServiceProvider()
		cmd, err := New(&protocol.MockProvider{}, msgRegistrar, webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, cmd)

		svcNames := []string{"svc-01", "svc-02", "svc-03", "svc-04"}
		for _, svcName := range svcNames {
			err := msgRegistrar.Register(generic.NewCustomMockMessageSvc("test", svcName))
			require.NoError(t, err)
		}

		require.Len(t, msgRegistrar.Services(), 4)

		const jsonStr = `{"name":"%s"}`
		for _, svcName := range svcNames {
			var b bytes.Buffer
			cmdErr := cmd.UnregisterService(&b, bytes.NewBufferString(fmt.Sprintf(jsonStr, svcName)))
			require.NoError(t, cmdErr)
			require.Empty(t, b.String())
		}

		require.Len(t, msgRegistrar.Services(), 0)
	})

	t.Run("Unregistering message service input decode failure", func(t *testing.T) {
		cmd, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.UnregisterService(&b, bytes.NewBufferString(`{--`))
		require.Error(t, cmdErr)
		require.Empty(t, b.String())
		require.Equal(t, cmdErr.Type(), command.ValidationError)
		require.Equal(t, cmdErr.Code(), InvalidRequestErrorCode)
		require.Contains(t, cmdErr.Error(), "invalid character")
	})
}

func TestCommand_Services(t *testing.T) {
	msgRegistrar := msghandler.NewMockMsgServiceProvider()
	cmd, err := New(&protocol.MockProvider{}, msgRegistrar, webhook.NewMockWebhookNotifier())
	require.NoError(t, err)
	require.NotNil(t, cmd)

	verifyResponse := func(buf *bytes.Buffer, count int) {
		response := RegisteredServicesResponse{}
		err = json.NewDecoder(buf).Decode(&response)
		require.NoError(t, err)

		require.NotEmpty(t, response)
		require.Len(t, response.Names, count)
	}

	var b bytes.Buffer
	cmdErr := cmd.Services(&b, bytes.NewBufferString(``))
	require.NoError(t, cmdErr)
	verifyResponse(&b, 0)

	testMsgSvcs := []dispatcher.MessageService{
		generic.NewCustomMockMessageSvc("type-01", "svc-name-01"),
		generic.NewCustomMockMessageSvc("type-02", "svc-name-02"),
		generic.NewCustomMockMessageSvc("type-03", "svc-name-03"),
		generic.NewCustomMockMessageSvc("type-04", "svc-name-04"),
		generic.NewCustomMockMessageSvc("type-05", "svc-name-05"),
	}
	err = msgRegistrar.Register(testMsgSvcs...)
	require.NoError(t, err)

	b.Reset()
	cmdErr = cmd.Services(&b, bytes.NewBufferString(``))
	require.NoError(t, cmdErr)
	verifyResponse(&b, len(testMsgSvcs))
}

func TestCommand_Send(t *testing.T) {
	t.Run("Test input args validation", func(t *testing.T) {
		tests := []struct {
			name        string
			requestJSON string
			errorCode   command.Code
			errorMsg    string
		}{
			{
				name:        "missing all params",
				requestJSON: `{}`,
				errorCode:   InvalidRequestErrorCode,
				errorMsg:    errMsgBodyEmpty,
			},
			{
				name:        "missing message body",
				requestJSON: `{"connection_ID": "dsfds"}`,
				errorCode:   InvalidRequestErrorCode,
				errorMsg:    errMsgBodyEmpty,
			},
			{
				name:        "missing destinations",
				requestJSON: `{"message_body": {"text":"sample msg 123"}}`,
				errorCode:   InvalidRequestErrorCode,
				errorMsg:    errMsgDestinationMissing,
			},
			{
				name:        "invalid service endpoint - missing endpoint",
				requestJSON: `{"message_body": {"text":"sample msg 123"}, "service_endpoint": {}}`,
				errorCode:   InvalidRequestErrorCode,
				errorMsg:    errMsgDestSvcEndpointMissing,
			},
			{
				name:        "invalid service endpoint - missing destination keys",
				requestJSON: `{"message_body": {"text":"sample"}, "service_endpoint": {"serviceEndpoint": "sdfsdf"}}`,
				errorCode:   InvalidRequestErrorCode,
				errorMsg:    errMsgDestSvcEndpointKeysMissing,
			},
			{
				name:        "invalid input",
				requestJSON: `{"message_body": -----}`,
				errorCode:   InvalidRequestErrorCode,
				errorMsg:    "invalid character",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				cmd, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
				require.NoError(t, err)
				require.NotNil(t, cmd)

				var b bytes.Buffer
				cmdErr := cmd.Send(&b, bytes.NewBufferString(tc.requestJSON))
				require.Error(t, cmdErr)
				require.Empty(t, b.String())
				require.Equal(t, cmdErr.Type(), command.ValidationError)
				require.Equal(t, cmdErr.Code(), tc.errorCode)
				require.Contains(t, cmdErr.Error(), tc.errorMsg)
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
				memProvider := mem.NewProvider()

				store, err := memProvider.OpenStore("didexchange")
				require.NoError(t, err)

				if tc.testConnection != nil {
					connBytes, errMarshal := json.Marshal(tc.testConnection)
					require.NoError(t, errMarshal)
					require.NoError(t, store.Put(fmt.Sprintf("conn_%s", tc.testConnection.ConnectionID), connBytes,
						spi.Tag{Name: "conn_"},
						spi.Tag{Name: "bothDIDs", Value: mockDIDTagFunc(tc.testConnection.MyDID, tc.testConnection.TheirDID)},
						spi.Tag{Name: "theirDID", Value: mockDIDTagFunc(tc.testConnection.TheirDID)},
					))
				}

				cmd, err := New(&protocol.MockProvider{
					StoreProvider:              memProvider,
					ProtocolStateStoreProvider: mem.NewProvider(),
				},
					msghandler.NewMockMsgServiceProvider(),
					webhook.NewMockWebhookNotifier())
				require.NoError(t, err)
				require.NotNil(t, cmd)

				var b bytes.Buffer
				cmdErr := cmd.Send(&b, bytes.NewBufferString(tc.requestJSON))
				require.NoError(t, cmdErr)
				require.Contains(t, b.String(), "{}")
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
			errorCode      command.Code
			errorMsg       string
		}{
			{
				name:           "send message to connection ID data not found error",
				testConnection: nil,
				requestJSON:    `{"message_body": {"text":"sample"}, "connection_id": "sample-conn-ID-001"}`,
				errorCode:      SendMsgError,
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
				errorCode:   SendMsgError,
				errorMsg:    "sample-err-01",
			},
			{
				name: "send message to their DID data not found error",
				testConnection: &connection.Record{
					ConnectionID: "sample-conn-ID-001",
					State:        "completed", MyDID: "mydid", TheirDID: "theirDID-z",
				},
				requestJSON: `{"message_body": {"text":"sample"}, "their_did": "theirDID-001"}`,
				errorCode:   SendMsgError,
				errorMsg:    vdrapi.ErrNotFound.Error(),
			},
			{
				name: "send message to destination",
				requestJSON: `{"message_body": {"text":"sample"},"service_endpoint": {"serviceEndpoint": "sdfsdf",
			"recipientKeys":["test"]}}`,
				messenger: &mocksvc.MockMessenger{ErrSendToDestination: fmt.Errorf("sample-err-01")},
				errorCode: SendMsgError,
				errorMsg:  "sample-err-01",
			},
			{
				name: "send message to destination",
				requestJSON: `{"message_body": {"text":"sample"},"service_endpoint": {"serviceEndpoint": "sdfsdf",
			"recipientKeys":["test"]}}`,
				kms:       &mockkms.KeyManager{CrAndExportPubKeyErr: fmt.Errorf("sample-kmserr-01")},
				errorCode: SendMsgError,
				errorMsg:  "sample-kmserr-01",
			},
			{
				name:        "failed to resolve destination from DID",
				requestJSON: `{"message_body": {"text":"sample"}, "their_did": "theirDID-001"}`,
				vdr:         &mockvdr.MockVDRegistry{ResolveErr: fmt.Errorf("sample-err-01")},
				errorCode:   SendMsgError,
				errorMsg:    "sample-err-01",
			},
			{
				name:        "invalid message body - scenario 1",
				requestJSON: `{"message_body": "sample-input", "their_did": "theirDID-001"}`,
				vdr: &mockvdr.MockVDRegistry{
					ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (doc *did.DocResolution, e error) {
						return &did.DocResolution{DIDDocument: mockdiddoc.GetMockDIDDoc(t, false)}, nil
					},
				},
				errorCode: SendMsgError,
				errorMsg:  "invalid payload data format",
			},
			{
				name: "invalid message body - scenario 2",
				testConnection: &connection.Record{
					ConnectionID: "sample-conn-ID-001",
					State:        "completed", MyDID: "mydid", TheirDID: "theirDID-001",
				},
				requestJSON: `{"message_body": "sample-input", "connection_id": "sample-conn-ID-001"}`,
				errorCode:   SendMsgError,
				errorMsg:    "invalid payload data format",
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				memProvider := mem.NewProvider()

				store, err := memProvider.OpenStore("didexchange")
				require.NoError(t, err)

				provider := &protocol.MockProvider{
					StoreProvider:              memProvider,
					ProtocolStateStoreProvider: mem.NewProvider(),
				}

				if tc.testConnection != nil {
					connBytes, errMarshal := json.Marshal(tc.testConnection)
					require.NoError(t, errMarshal)
					require.NoError(t, store.Put(fmt.Sprintf("conn_%s", tc.testConnection.ConnectionID), connBytes,
						spi.Tag{Name: "conn_"}))
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

				cmd, err := New(provider, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
				require.NoError(t, err)
				require.NotNil(t, cmd)

				var b bytes.Buffer
				cmdErr := cmd.Send(&b, bytes.NewBufferString(tc.requestJSON))
				require.Error(t, cmdErr)
				require.Empty(t, b.String())
				require.Equal(t, cmdErr.Type(), command.ExecuteError)
				require.Equal(t, cmdErr.Code(), tc.errorCode)
				require.Contains(t, cmdErr.Error(), tc.errorMsg)
			})
		}
	})
}

func TestCommand_Reply(t *testing.T) {
	t.Run("Test reply validation and failures", func(t *testing.T) {
		tests := []struct {
			name        string
			requestJSON string
			messenger   *mocksvc.MockMessenger
			errorCode   command.Code
			errorMsg    string
			errType     command.Type
		}{
			{
				name:        "missing all params",
				requestJSON: `{}`,
				errorCode:   InvalidRequestErrorCode,
				errorMsg:    errMsgBodyEmpty,
				errType:     command.ValidationError,
			},
			{
				name:        "missing message body",
				requestJSON: `{"message_ID": "1234"}`,
				errorCode:   InvalidRequestErrorCode,
				errorMsg:    errMsgBodyEmpty,
				errType:     command.ValidationError,
			},
			{
				name:        "missing message id",
				requestJSON: `{"message_body": "sample"}`,
				errorCode:   InvalidRequestErrorCode,
				errorMsg:    errMsgIDEmpty,
				errType:     command.ValidationError,
			},
			{
				name:        "invalid request",
				requestJSON: `----`,
				errorCode:   InvalidRequestErrorCode,
				errorMsg:    "invalid character",
				errType:     command.ValidationError,
			},
			{
				name:        "invalid message format",
				requestJSON: `{"message_ID": "1234","message_body": "sample-msg"}`,
				errorCode:   SendMsgReplyError,
				errorMsg:    "invalid payload data format",
				errType:     command.ExecuteError,
			},
			{
				name:        "invalid message format",
				requestJSON: `{"message_ID": "1234","message_body": {"msg":"Hello !!"}}`,
				messenger:   &mocksvc.MockMessenger{ErrReplyTo: fmt.Errorf("sample-err-01")},
				errorCode:   SendMsgReplyError,
				errorMsg:    "sample-err-01",
				errType:     command.ExecuteError,
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

				cmd, err := New(provider, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
				require.NoError(t, err)
				require.NotNil(t, cmd)

				var b bytes.Buffer
				cmdErr := cmd.Reply(&b, bytes.NewBufferString(tc.requestJSON))
				require.Error(t, cmdErr)
				require.Empty(t, b.String())
				require.Equal(t, cmdErr.Type(), tc.errType)
				require.Equal(t, cmdErr.Code(), tc.errorCode)
				require.Contains(t, cmdErr.Error(), tc.errorMsg)
			})
		}
	})

	t.Run("Test send message reply", func(t *testing.T) {
		const jsonMsg = `{"message_ID": "1234","message_body": {"msg":"Hello !!"}}`
		cmd, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.Reply(&b, bytes.NewBufferString(jsonMsg))
		require.NoError(t, cmdErr)
	})

	t.Run("Test send message reply by starting new thread", func(t *testing.T) {
		const jsonMsg = `{"message_ID": "1234","message_body": {"msg":"Hello !!"}, "start_new_thread": true}`
		cmd, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), webhook.NewMockWebhookNotifier())
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		cmdErr := cmd.Reply(&b, bytes.NewBufferString(jsonMsg))
		require.NoError(t, cmdErr)
	})
}
