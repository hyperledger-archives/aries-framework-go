/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messaging

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
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
		client, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), &mockNotifier{})
		require.NoError(t, err)
		require.NotNil(t, client)
	})

	t.Run("Test create new command success failure", func(t *testing.T) {
		const errMsg = "sample-error"
		client, err := New(&protocol.MockProvider{
			StoreProvider: &storage.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf(errMsg),
			},
		}, msghandler.NewMockMsgServiceProvider(), &mockNotifier{})
		require.Error(t, err)
		require.Nil(t, client)
		require.Contains(t, err.Error(), errMsg)
	})
}

func TestCommand_RegisterService(t *testing.T) {
	t.Run("Successful Register Message Service", func(t *testing.T) {
		msgRegistrar := msghandler.NewMockMsgServiceProvider()
		cmd, err := New(&protocol.MockProvider{}, msgRegistrar, &mockNotifier{})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		err = cmd.RegisterService("json-msg-01", "https://didcomm.org/json/1.0/msg", "prp-01", "prp-02")
		require.NoError(t, err)

		// verify if new service is registered
		require.NotEmpty(t, msgRegistrar.Services())
		require.Equal(t, "json-msg-01", msgRegistrar.Services()[0].Name())
		require.True(t, msgRegistrar.Services()[0].Accept(
			"https://didcomm.org/json/1.0/msg",
			[]string{"prp-01", "prp-02"},
		))
	})

	t.Run("Register Message Service failure", func(t *testing.T) {
		const errMsg = "sample-error"
		mhandler := msghandler.NewMockMsgServiceProvider()
		mhandler.RegisterErr = fmt.Errorf(errMsg)

		cmd, err := New(&protocol.MockProvider{}, mhandler, &mockNotifier{})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		err = cmd.RegisterService("json-msg-01", "https://didcomm.org/json/1.0/msg", "prp-01", "prp-02")
		require.Error(t, err)
		require.Contains(t, err.Error(), errMsg)
	})
}

func TestCommand_UnregisterService(t *testing.T) {
	t.Run("Unregistering non existing message service", func(t *testing.T) {
		cmd, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), &mockNotifier{})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		err = cmd.UnregisterService("json-msg-01")
		require.Error(t, err)
	})

	t.Run("Unregistering message service successfully", func(t *testing.T) {
		msgRegistrar := msghandler.NewMockMsgServiceProvider()
		cmd, err := New(&protocol.MockProvider{}, msgRegistrar, &mockNotifier{})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		svcNames := []string{"svc-01", "svc-02", "svc-03", "svc-04"}
		for _, svcName := range svcNames {
			err := msgRegistrar.Register(generic.NewCustomMockMessageSvc("test", svcName))
			require.NoError(t, err)
		}

		require.Len(t, msgRegistrar.Services(), 4)

		for _, svcName := range svcNames {
			err := cmd.UnregisterService(svcName)
			require.NoError(t, err)
		}

		require.Len(t, msgRegistrar.Services(), 0)
	})
}

func TestCommand_Services(t *testing.T) {
	msgRegistrar := msghandler.NewMockMsgServiceProvider()
	cmd, err := New(&protocol.MockProvider{}, msgRegistrar, &mockNotifier{})
	require.NoError(t, err)
	require.NotNil(t, cmd)

	svcs := cmd.Services()
	require.Empty(t, svcs)

	testMsgSvcs := []dispatcher.MessageService{
		generic.NewCustomMockMessageSvc("type-01", "svc-name-01"),
		generic.NewCustomMockMessageSvc("type-02", "svc-name-02"),
		generic.NewCustomMockMessageSvc("type-03", "svc-name-03"),
		generic.NewCustomMockMessageSvc("type-04", "svc-name-04"),
		generic.NewCustomMockMessageSvc("type-05", "svc-name-05"),
	}
	err = msgRegistrar.Register(testMsgSvcs...)
	require.NoError(t, err)

	svcs = cmd.Services()
	require.Len(t, svcs, len(testMsgSvcs))
}

func TestCommand_Send(t *testing.T) { // nolint: gocognit, gocyclo
	t.Run("Test send new message success", func(t *testing.T) {
		tests := []struct {
			name           string
			testConnection *connection.Record
			msgBody        string
			option         SendMessageOpions
		}{
			{
				name: "send message to connection ID",
				testConnection: &connection.Record{
					ConnectionID: "sample-conn-ID-001",
					State:        "completed", MyDID: "mydid", TheirDID: "theirDID-001",
				},
				option: SendByConnectionID("sample-conn-ID-001"),
			},
			{
				name: "send message to their DID",
				testConnection: &connection.Record{
					ConnectionID: "sample-conn-ID-001",
					State:        "completed", MyDID: "mydid", TheirDID: "theirDID-001",
				},
				option: SendByTheirDID("theirDID-001"),
			},
			{
				name: "send message to destination",
				option: SendByDestination(&service.Destination{
					RecipientKeys:   []string{"test"},
					ServiceEndpoint: model.NewDIDCommV1Endpoint("dfsdf"),
					RoutingKeys:     []string{"test"},
				}),
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

				memStore, err := memProvider.OpenStore("didexchange")
				require.NoError(t, err)

				if tc.testConnection != nil {
					connBytes, errMarshal := json.Marshal(tc.testConnection)
					require.NoError(t, errMarshal)
					require.NoError(t,
						memStore.Put(fmt.Sprintf("conn_%s", tc.testConnection.ConnectionID), connBytes,
							spi.Tag{Name: "conn_"},
							spi.Tag{Name: "bothDIDs", Value: mockDIDTagFunc(tc.testConnection.MyDID, tc.testConnection.TheirDID)},
							spi.Tag{Name: "theirDID", Value: mockDIDTagFunc(tc.testConnection.TheirDID)},
						))
				}

				cmd, err := New(&protocol.MockProvider{
					StoreProvider:              memProvider,
					ProtocolStateStoreProvider: mem.NewProvider(),
				},
					msghandler.NewMockMsgServiceProvider(), &mockNotifier{})
				require.NoError(t, err)
				require.NotNil(t, cmd)

				var b bytes.Buffer
				res, err := cmd.Send(json.RawMessage([]byte(`{"text":"sample"}`)), tc.option)
				require.NoError(t, err)
				require.Empty(t, b.String())
				require.Empty(t, res)
			})
		}
	})

	const msgStr = `{"@id": "2d798168-8abf-4410-8535-bc1e8406a5ff","text":"sample"}`

	const replyMsgStr = `{
							"@id": "123456781",
							"@type": "sample-response-type",
							"~thread" : {"thid": "2d798168-8abf-4410-8535-bc1e8406a5ff"}
					}`

	t.Run("Test send new message and await response success", func(t *testing.T) {
		tests := []struct {
			name           string
			testConnection *connection.Record
			msgBody        string
			option         []SendMessageOpions
		}{
			{
				name: "send message to connection ID",
				testConnection: &connection.Record{
					ConnectionID: "sample-conn-ID-001",
					State:        "completed", MyDID: "mydid", TheirDID: "theirDID-001",
				},
				option: []SendMessageOpions{
					SendByConnectionID("sample-conn-ID-001"),
					WaitForResponse(context.Background(), "sample-response-type"),
				},
			},
			{
				name: "send message to their DID",
				testConnection: &connection.Record{
					ConnectionID: "sample-conn-ID-001",
					State:        "completed", MyDID: "mydid", TheirDID: "theirDID-001",
				},
				option: []SendMessageOpions{
					SendByTheirDID("theirDID-001"),
					WaitForResponse(context.Background(), "sample-response-type"),
				},
			},
			{
				name: "send message to destination",
				option: []SendMessageOpions{
					SendByDestination(&service.Destination{
						RecipientKeys:   []string{"test"},
						ServiceEndpoint: model.NewDIDCommV1Endpoint("sdfsdf"),
						RoutingKeys:     []string{"test"},
					}),
					WaitForResponse(context.Background(), "sample-response-type"),
				},
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

				memStore, err := memProvider.OpenStore("didexchange")
				require.NoError(t, err)

				if tc.testConnection != nil {
					connBytes, errMarshal := json.Marshal(tc.testConnection)
					require.NoError(t, errMarshal)
					require.NoError(t,
						memStore.Put(fmt.Sprintf("conn_%s", tc.testConnection.ConnectionID), connBytes,
							spi.Tag{Name: "conn_"},
							spi.Tag{Name: "bothDIDs", Value: mockDIDTagFunc(tc.testConnection.MyDID, tc.testConnection.TheirDID)},
							spi.Tag{Name: "theirDID", Value: mockDIDTagFunc(tc.testConnection.TheirDID)},
						))
				}

				registrar := msghandler.NewMockMsgServiceProvider()

				cmd, err := New(&protocol.MockProvider{
					StoreProvider:              memProvider,
					ProtocolStateStoreProvider: mem.NewProvider(),
				},
					registrar, &mockNotifier{})
				require.NoError(t, err)
				require.NotNil(t, cmd)

				replyMsg, err := service.ParseDIDCommMsgMap([]byte(replyMsgStr))
				require.NoError(t, err)

				go func() {
					for {
						services := registrar.Services()
						if len(services) > 0 {
							_, e := services[0].HandleInbound(replyMsg, service.NewDIDCommContext("sampleDID", "sampleTheirDID", nil))
							require.NoError(t, e)

							break
						}
					}
				}()

				res, err := cmd.Send(
					json.RawMessage(msgStr),
					tc.option...)
				require.NoError(t, err)

				var response map[string]interface{}
				err = json.Unmarshal(res, &response)
				require.NoError(t, err)
				require.NotEmpty(t, response)
				require.NotEmpty(t, response["message"])
			})
		}
	})

	t.Run("Test send new message failures with bad context", func(t *testing.T) {
		badContext, cancel := context.WithTimeout(context.Background(), 0*time.Second)
		defer cancel()

		connBytes, err := json.Marshal(&connection.Record{
			ConnectionID: "sample-conn-ID-001",
			State:        "completed", MyDID: "mydid", TheirDID: "theirDID-001",
		})
		require.NoError(t, err)

		mockStore := &storage.MockStore{Store: make(map[string]storage.DBEntry)}
		require.NoError(t, mockStore.Put("conn_sample-conn-ID-001", connBytes))

		cmd, err := New(&protocol.MockProvider{StoreProvider: storage.NewCustomMockStoreProvider(mockStore)},
			msghandler.NewMockMsgServiceProvider(), &mockNotifier{})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		res, err := cmd.Send(
			json.RawMessage([]byte(msgStr)),
			SendByConnectionID("sample-conn-ID-001"),
			WaitForResponse(badContext, "sample-rep-type"),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get reply, context deadline exceeded")
		require.Empty(t, res)
	})

	t.Run("Test send new message failures", func(t *testing.T) {
		tests := []struct {
			name           string
			testConnection *connection.Record
			messenger      *mocksvc.MockMessenger
			kms            *mockkms.KeyManager
			vdr            *mockvdr.MockVDRegistry
			option         SendMessageOpions
			errorMsg       string
			msgBody        json.RawMessage
		}{
			{
				name:           "send message to connection ID data not found error",
				testConnection: nil,
				errorMsg:       "data not found",
				option:         SendByConnectionID("sample-conn-ID-001"),
			},
			{
				name:           "send message without any options",
				testConnection: nil,
				errorMsg:       "missing message destination",
				option:         SendByConnectionID(""),
			},
			{
				name: "send message to connection ID send error",
				testConnection: &connection.Record{
					ConnectionID: "sample-conn-ID-001",
					State:        "completed", MyDID: "mydid", TheirDID: "theirDID-001",
				},
				option:    SendByConnectionID("sample-conn-ID-001"),
				messenger: &mocksvc.MockMessenger{ErrSend: fmt.Errorf("sample-err-01")},
				errorMsg:  "sample-err-01",
			},
			{
				name: "send message to their DID data not found error",
				testConnection: &connection.Record{
					ConnectionID: "sample-conn-ID-001",
					State:        "completed", MyDID: "mydid", TheirDID: "theirDID-z",
				},
				option:   SendByTheirDID("theirDID-001"),
				errorMsg: vdrapi.ErrNotFound.Error(),
			},
			{
				name: "send message to destination - failure 1",
				option: SendByDestination(&service.Destination{
					RecipientKeys:   []string{"test"},
					ServiceEndpoint: model.NewDIDCommV1Endpoint("sdfsdf"),
					RoutingKeys:     []string{"test"},
				}),
				messenger: &mocksvc.MockMessenger{ErrSendToDestination: fmt.Errorf("sample-err-01")},
				errorMsg:  "sample-err-01",
			},
			{
				name: "send message to destination - failure 2",
				kms:  &mockkms.KeyManager{CrAndExportPubKeyErr: fmt.Errorf("sample-kmserr-01")},
				option: SendByDestination(&service.Destination{
					RecipientKeys:   []string{"test"},
					ServiceEndpoint: model.NewDIDCommV1Endpoint("sdfsdf"),
					RoutingKeys:     []string{"test"},
				}),
				errorMsg: "sample-kmserr-01",
			},
			{
				name:     "failed to resolve destination from DID",
				option:   SendByTheirDID("theirDID-001"),
				vdr:      &mockvdr.MockVDRegistry{ResolveErr: fmt.Errorf("sample-err-01")},
				errorMsg: "sample-err-01",
			},
			{
				name:   "invalid message body - scenario 1",
				option: SendByTheirDID("theirDID-001"),
				vdr: &mockvdr.MockVDRegistry{
					ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (doc *did.DocResolution, e error) {
						return &did.DocResolution{DIDDocument: mockdiddoc.GetMockDIDDoc(t, false)}, nil
					},
				},
				errorMsg: "invalid payload data format",
				msgBody:  json.RawMessage([]byte("--")),
			},
			{
				name: "invalid message body - scenario 2",
				testConnection: &connection.Record{
					ConnectionID: "sample-conn-ID-001",
					State:        "completed", MyDID: "mydid", TheirDID: "theirDID-001",
				},
				option:   SendByConnectionID("sample-conn-ID-001"),
				errorMsg: "invalid payload data format",
				msgBody:  json.RawMessage([]byte("--")),
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				provider := &protocol.MockProvider{ProtocolStateStoreProvider: mem.NewProvider()}

				memProvider := mem.NewProvider()

				memStore, err := memProvider.OpenStore("didexchange")
				require.NoError(t, err)

				if tc.testConnection != nil {
					connBytes, errMarshal := json.Marshal(tc.testConnection)
					require.NoError(t, errMarshal)

					require.NoError(t, memStore.Put(fmt.Sprintf("conn_%s", tc.testConnection.ConnectionID), connBytes))
				}

				provider.StoreProvider = memProvider

				if tc.messenger != nil {
					provider.CustomMessenger = tc.messenger
				}

				if tc.kms != nil {
					provider.CustomKMS = tc.kms
				}

				if tc.vdr != nil {
					provider.CustomVDR = tc.vdr
				}

				cmd, err := New(provider, msghandler.NewMockMsgServiceProvider(), &mockNotifier{})
				require.NoError(t, err)
				require.NotNil(t, cmd)

				msgBody := json.RawMessage([]byte(`{"text":"sample"}`))

				if tc.msgBody != nil {
					msgBody = tc.msgBody
				}

				res, err := cmd.Send(msgBody, tc.option)
				require.Error(t, err, "failed test : %s", tc.name)
				require.Contains(t, err.Error(), tc.errorMsg)
				require.Empty(t, res)
			})
		}
	})
}

func TestCommand_Reply(t *testing.T) {
	t.Run("Test reply validation and failures", func(t *testing.T) {
		tests := []struct {
			name      string
			msgBody   string
			msgID     string
			messenger *mocksvc.MockMessenger
			errorMsg  string
		}{
			{
				name:     "invalid message format",
				msgBody:  `"sample-msg"`,
				errorMsg: "invalid payload data format",
			},
			{
				name:      "message reply error",
				msgBody:   `{"msg":"Hello !!"}`,
				messenger: &mocksvc.MockMessenger{ErrReplyTo: fmt.Errorf("sample-err-01")},
				errorMsg:  "sample-err-01",
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

				cmd, err := New(provider, msghandler.NewMockMsgServiceProvider(), &mockNotifier{})
				require.NoError(t, err)
				require.NotNil(t, cmd)

				res, err := cmd.Reply(context.Background(), json.RawMessage([]byte(tc.msgBody)), tc.msgID, false, "")
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errorMsg)
				require.Empty(t, res)
			})
		}
	})

	t.Run("Test send message reply", func(t *testing.T) {
		cmd, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), &mockNotifier{})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		res, err := cmd.Reply(context.Background(), json.RawMessage([]byte(`{"msg":"Hello !!"}`)), "msg-id", false, "")
		require.NoError(t, err)
		require.Empty(t, res)
	})

	t.Run("Test send message reply by starting new thread", func(t *testing.T) {
		cmd, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), &mockNotifier{})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		res, err := cmd.Reply(context.Background(), json.RawMessage([]byte(`{"msg":"Hello !!"}`)), "msg-id", true, "")
		require.NoError(t, err)
		require.Empty(t, res)
	})

	const msgStr = `{"@id": "2d798168-8abf-4410-8535-bc1e8406a5ff","text":"sample"}`

	const replyMsgStr = `{
							"@id": "123456781",
							"@type": "sample-response-type",
							"~thread" : {"thid": "2d798168-8abf-4410-8535-bc1e8406a5ff"}
					}`

	t.Run("Test send message reply and await response", func(t *testing.T) {
		registrar := msghandler.NewMockMsgServiceProvider()

		cmd, err := New(&protocol.MockProvider{}, registrar, &mockNotifier{})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		replyMsg, err := service.ParseDIDCommMsgMap([]byte(replyMsgStr))
		require.NoError(t, err)

		go func() {
			for {
				services := registrar.Services()

				if len(services) > 0 {
					_, e := services[0].HandleInbound(replyMsg, service.NewDIDCommContext("sampleDID", "sampleTheirDID", nil))
					require.NoError(t, e)
				}
			}
		}()

		res, err := cmd.Reply(context.Background(), json.RawMessage([]byte(msgStr)), "msg-id", false, "sample-response-type")
		require.NoError(t, err)

		var response map[string]interface{}
		err = json.Unmarshal(res, &response)
		require.NoError(t, err)
		require.NotEmpty(t, response)
		require.NotEmpty(t, response["message"])
	})

	t.Run("Test send message reply by starting new thread  and await response", func(t *testing.T) {
		registrar := msghandler.NewMockMsgServiceProvider()

		cmd, err := New(&protocol.MockProvider{}, registrar, &mockNotifier{})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		replyMsg, err := service.ParseDIDCommMsgMap([]byte(replyMsgStr))
		require.NoError(t, err)

		go func() {
			for {
				svcs := registrar.Services()
				if len(svcs) > 0 {
					_, e := svcs[0].HandleInbound(
						replyMsg, service.NewDIDCommContext("sampleDID", "sampleTheirDID", nil))
					require.NoError(t, e)
				}
			}
		}()

		res, err := cmd.Reply(context.Background(), json.RawMessage([]byte(msgStr)), "msg-id", true, "sample-response-type")
		require.NoError(t, err)

		var response map[string]interface{}
		err = json.Unmarshal(res, &response)
		require.NoError(t, err)
		require.NotEmpty(t, response)
		require.NotEmpty(t, response["message"])
	})
}

// mockNotifier is mock implementation of Notifier.
type mockNotifier struct {
	NotifyFunc func(topic string, message []byte) error
}

// Notify is mock implementation of Notifier Notify().
func (n *mockNotifier) Notify(topic string, message []byte) error {
	if n.NotifyFunc != nil {
		return n.NotifyFunc(topic, message)
	}

	return nil
}
