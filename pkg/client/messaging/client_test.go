/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messaging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

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

func TestCommand_Send(t *testing.T) {
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
					ServiceEndpoint: "sdfsdf",
					RoutingKeys:     []string{"test"},
				}),
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.name, func(t *testing.T) {
				mockStore := &storage.MockStore{Store: make(map[string][]byte)}
				if tc.testConnection != nil {
					connBytes, err := json.Marshal(tc.testConnection)
					require.NoError(t, err)
					require.NoError(t, mockStore.Put(fmt.Sprintf("conn_%s", tc.testConnection.ConnectionID), connBytes))
				}

				cmd, err := New(&protocol.MockProvider{StoreProvider: storage.NewCustomMockStoreProvider(mockStore)},
					msghandler.NewMockMsgServiceProvider(), &mockNotifier{})
				require.NoError(t, err)
				require.NotNil(t, cmd)

				var b bytes.Buffer
				err = cmd.Send(json.RawMessage([]byte(`{"text":"sample"}`)), tc.option)
				require.NoError(t, err)
				require.Empty(t, b.String())
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
				errorMsg: "DID not found",
			},
			{
				name: "send message to destination - failure 1",
				option: SendByDestination(&service.Destination{
					RecipientKeys:   []string{"test"},
					ServiceEndpoint: "sdfsdf",
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
					ServiceEndpoint: "sdfsdf",
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
					ResolveFunc: func(didID string, opts ...vdrapi.ResolveOpts) (doc *did.Doc, e error) {
						return mockdiddoc.GetMockDIDDoc(), nil
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
				provider := &protocol.MockProvider{}

				if tc.testConnection != nil {
					mockStore := &storage.MockStore{Store: make(map[string][]byte)}
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

				cmd, err := New(provider, msghandler.NewMockMsgServiceProvider(), &mockNotifier{})
				require.NoError(t, err)
				require.NotNil(t, cmd)

				msgBody := json.RawMessage([]byte(`{"text":"sample"}`))

				if tc.msgBody != nil {
					msgBody = tc.msgBody
				}

				cmdErr := cmd.Send(msgBody, tc.option)
				require.Error(t, cmdErr, "failed test : %s", tc.name)
				require.Contains(t, cmdErr.Error(), tc.errorMsg)
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

				err = cmd.Reply(json.RawMessage([]byte(tc.msgBody)), tc.msgID, false)
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errorMsg)
			})
		}
	})

	t.Run("Test send message reply", func(t *testing.T) {
		cmd, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), &mockNotifier{})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		err = cmd.Reply(json.RawMessage([]byte(`{"msg":"Hello !!"}`)), "msg-id", false)
		require.NoError(t, err)
	})

	t.Run("Test send message reply by starting new thread", func(t *testing.T) {
		cmd, err := New(&protocol.MockProvider{}, msghandler.NewMockMsgServiceProvider(), &mockNotifier{})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		err = cmd.Reply(json.RawMessage([]byte(`{"msg":"Hello !!"}`)), "msg-id", true)
		require.NoError(t, err)
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
