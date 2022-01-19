/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package inbound

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/middleware"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/msghandler"
	mockdidexchange "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/generic"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	didstore "github.com/hyperledger/aries-framework-go/pkg/store/did"
)

func TestNewInboundMessageHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		_ = NewInboundMessageHandler(emptyProvider())
	})
}

func TestMessageHandler_HandlerFunc(t *testing.T) {
	handler := NewInboundMessageHandler(emptyProvider())

	handleFunc := handler.HandlerFunc()

	err := handleFunc(&transport.Envelope{
		Message: []byte(`{
	"@id":"12345",
	"@type":"message-type"
}`),
	})
	require.NoError(t, err)
}

func TestMessageHandler_HandleInboundEnvelope(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testCases := []struct {
		testName        string
		svcAccept       string
		svcName         string
		svcHandleErr    error
		getDIDsErr      error
		msgSvcAccept    bool
		msgSvcHandleErr error
		messengerErr    error
		message         string
		expectErr       string
	}{
		{
			testName:  "success: without getDIDs",
			svcAccept: "message-type",
			svcName:   didexchange.DIDExchange,
			message: `{
	"@id":"12345",
	"@type":"message-type"
}`,
		},
		{
			testName:  "success: with getDIDs",
			svcAccept: "message-type",
			svcName:   "service-name",
			message: `{
	"@id":"12345",
	"@type":"message-type"
}`,
		},
		{
			testName:  "success: didcomm v2",
			svcAccept: "message-type",
			message: `{
	"id":"12345",
	"type":"message-type",
	"body":{}
}`,
		},
		{
			testName:  "fail: parsing message",
			message:   `{`,
			expectErr: "invalid payload data format",
		},
		{
			testName: "fail: can't determine if didcomm v1 or v2",
			message: `{
	"body":{},
	"~thread":"12345"
}`,
			expectErr: "not a valid didcomm v1 or v2 message",
		},
		{
			testName:   "fail: getDIDs error",
			svcAccept:  "message-type",
			svcName:    "service-name",
			getDIDsErr: fmt.Errorf("get DIDs error"),
			message: `{
	"@id":"12345",
	"@type":"message-type"
}`,
			expectErr: "get DIDs error",
		},
		{
			testName:   "fail: getDIDs error for didcomm v2",
			svcAccept:  "message-type",
			svcName:    "service-name",
			getDIDsErr: fmt.Errorf("get DIDs error"),
			message: `{
	"id":"12345",
	"type":"message-type",
	"body":{}
}`,
			expectErr: "get DIDs error",
		},
		{
			testName:  "fail: didcomm v2 did rotation error",
			svcAccept: "message-type",
			message: `{
	"id":"12345",
	"type":"message-type",
	"from_prior":{},
	"body":{}
}`,
			expectErr: "field should be a string",
		},
		{
			testName:  "success: messenger service",
			svcAccept: "message-type",
			message: `{
	"@id":"12345",
	"@type":"different-type"
}`,
			msgSvcAccept: true,
		},
		{
			testName:  "fail: bad message purpose field",
			svcAccept: "message-type",
			message: `{
	"@id":"12345",
	"@type":"different-type",
	"~purpose": {"aaaaa":"bbbbb"}
}`,
			expectErr: "expected type 'string'",
		},
		{
			testName:  "fail: error in getDIDs for message service",
			svcAccept: "message-type",
			message: `{
	"@id":"12345",
	"@type":"different-type"
}`,
			msgSvcAccept: true,
			getDIDsErr:   fmt.Errorf("get DIDs error"),
			expectErr:    "get DIDs error",
		},
		{
			testName:  "fail: error in messenger HandleInbound",
			svcAccept: "message-type",
			message: `{
	"@id":"12345",
	"@type":"different-type"
}`,
			msgSvcAccept: true,
			messengerErr: fmt.Errorf("messenger error"),
			expectErr:    "messenger error",
		},
		{
			testName:  "fail: error in message service HandleInbound",
			svcAccept: "message-type",
			message: `{
	"@id":"12345",
	"@type":"different-type"
}`,
			msgSvcAccept:    true,
			msgSvcHandleErr: fmt.Errorf("message svc error"),
			expectErr:       "message svc error",
		},
		{
			testName:  "fail: no handler for given message",
			svcAccept: "message-type",
			message: `{
	"@id":"12345",
	"@type":"different-type"
}`,
			expectErr: "no message handlers found",
		},
		{
			testName:  "fail: no handler for given didcomm v2 message",
			svcAccept: "message-type",
			message: `{
	"id":"12345",
	"type":"different-type",
	"body":{}
}`,
			msgSvcAccept: true,
			expectErr:    "no message handlers found",
		},
	}

	store := mockstore.NewMockStoreProvider()
	psStore := mockstore.NewMockStoreProvider()

	p := mockprovider.Provider{
		StorageProviderValue:              store,
		ProtocolStateStorageProviderValue: psStore,
	}

	connectionRecorder, err := connection.NewRecorder(&p)
	require.NoError(t, err)

	myDID := "did:test:my-did"
	theirDID := "did:test:their-did"

	err = connectionRecorder.SaveConnectionRecord(&connection.Record{
		ConnectionID:  "12345",
		MyDID:         myDID,
		TheirDID:      theirDID,
		State:         connection.StateNameCompleted,
		MyDIDRotation: nil,
	})
	require.NoError(t, err)

	didRotator, err := middleware.New(&p)
	require.NoError(t, err)

	t.Parallel()

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			msgSvcProvider := msghandler.MockMsgSvcProvider{}

			require.NoError(t, msgSvcProvider.Register(&generic.MockMessageSvc{
				AcceptFunc: func(msgType string, purpose []string) bool {
					return tc.msgSvcAccept
				},
				HandleFunc: func(msg *service.DIDCommMsg) (string, error) {
					return "", tc.msgSvcHandleErr
				},
			}))

			messengerHandler := mocks.NewMockMessengerHandler(ctrl)
			messengerHandler.EXPECT().HandleInbound(gomock.Any(), gomock.Any()).AnyTimes().Return(tc.messengerErr)

			didex := mockdidexchange.MockDIDExchangeSvc{
				ProtocolName: tc.svcName,
				AcceptFunc: func(s string) bool {
					return s == tc.svcAccept
				},
				HandleFunc: func(msg service.DIDCommMsg) (string, error) {
					return "", tc.svcHandleErr
				},
			}

			prov := mockprovider.Provider{
				DIDConnectionStoreValue: &mockDIDStore{getDIDErr: tc.getDIDsErr, results: map[string]mockDIDResult{
					base58.Encode([]byte("my_key")):    {did: myDID},
					base58.Encode([]byte("their_key")): {did: theirDID},
				}},
				MessageServiceProviderValue: &msgSvcProvider,
				InboundMessengerValue:       messengerHandler,
				ServiceValue:                &didex,
				DIDRotatorValue:             *didRotator,
			}

			h := NewInboundMessageHandler(&prov)

			err = h.HandleInboundEnvelope(&transport.Envelope{
				Message: []byte(tc.message),
				ToKey:   []byte("my_key"),
				FromKey: []byte("their_key"),
			})
			if tc.expectErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectErr)
			}
		})
	}
}

func TestMessageHandler_Initialize(t *testing.T) {
	p := emptyProvider()

	// second Initialize is no-op
	h := &MessageHandler{}
	h.Initialize(p)
	h.Initialize(p)

	// first Initialize is in New, second is no-op
	h = NewInboundMessageHandler(p)
	h.Initialize(p)
}

func TestMessageHandler_getDIDs(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := emptyProvider()

		h := NewInboundMessageHandler(p)

		myDID, theirDID, err := h.getDIDs(&transport.Envelope{
			ToKey:   []byte("abcd"),
			FromKey: []byte("abcd"),
		}, nil)

		require.NoError(t, err)
		require.Equal(t, "", myDID)
		require.Equal(t, "", theirDID)
	})

	t.Run("success: dids from key refs", func(t *testing.T) {
		p := emptyProvider()

		h := NewInboundMessageHandler(p)

		myDID, theirDID, err := h.getDIDs(&transport.Envelope{
			ToKey:   []byte(`{"kid":"did:peer:alice#key-1"}`),
			FromKey: []byte(`{"kid":"did:peer:bob#key-1"}`),
		}, nil)

		require.NoError(t, err)
		require.Equal(t, "did:peer:alice", myDID)
		require.Equal(t, "did:peer:bob", theirDID)
	})

	t.Run("success: their DID from message", func(t *testing.T) {
		p := emptyProvider()

		h := NewInboundMessageHandler(p)

		myDID, theirDID, err := h.getDIDs(&transport.Envelope{
			ToKey:   []byte(`{"kid":"did:peer:alice#key-1"}`),
			FromKey: nil,
		}, service.DIDCommMsgMap{
			"from": "did:peer:bob",
		})

		require.NoError(t, err)
		require.Equal(t, "did:peer:alice", myDID)
		require.Equal(t, "did:peer:bob", theirDID)
	})

	t.Run("fail: bad did key", func(t *testing.T) {
		p := emptyProvider()

		h := NewInboundMessageHandler(p)

		_, _, err := h.getDIDs(&transport.Envelope{
			ToKey: []byte(`abcd # abcd "kid":"did:`), // matches string matching, but is not JSON
		}, nil)

		require.Error(t, err)
		require.Contains(t, err.Error(), "pubKeyToDID: unmarshal key")

		_, _, err = h.getDIDs(&transport.Envelope{
			FromKey: []byte(`abcd # abcd "kid":"did:`), // matches string matching, but is not JSON
		}, nil)

		require.Error(t, err)
		require.Contains(t, err.Error(), "pubKeyToDID: unmarshal key")
	})

	t.Run("fail: can't get my did", func(t *testing.T) {
		p := emptyProvider()
		p.DIDConnectionStoreValue = &mockDIDStore{
			results: map[string]mockDIDResult{
				base58.Encode([]byte("my_key")):    {did: "bbb", err: fmt.Errorf("mock did store error")},
				base58.Encode([]byte("their_key")): {did: "aaa", err: nil},
			},
		}
		p.GetDIDsMaxRetriesValue = 1

		h := NewInboundMessageHandler(p)

		_, _, err := h.getDIDs(&transport.Envelope{
			ToKey:   []byte("my_key"),
			FromKey: []byte("their_key"),
		}, nil)

		require.Error(t, err)
		require.Contains(t, err.Error(), "mock did store error")
	})

	t.Run("fail: can't get their did", func(t *testing.T) {
		p := emptyProvider()
		p.DIDConnectionStoreValue = &mockDIDStore{
			results: map[string]mockDIDResult{
				base58.Encode([]byte("my_key")):    {did: "aaa", err: nil},
				base58.Encode([]byte("their_key")): {did: "bbb", err: fmt.Errorf("mock did store error")},
			},
		}
		p.GetDIDsMaxRetriesValue = 1

		h := NewInboundMessageHandler(p)

		_, _, err := h.getDIDs(&transport.Envelope{
			ToKey:   []byte("my_key"),
			FromKey: []byte("their_key"),
		}, nil)

		require.Error(t, err)
		require.Contains(t, err.Error(), "mock did store error")
	})

	t.Run("not found", func(t *testing.T) {
		p := emptyProvider()
		p.DIDConnectionStoreValue = &mockDIDStore{
			getDIDErr: didstore.ErrNotFound,
		}
		p.GetDIDsMaxRetriesValue = 1

		h := NewInboundMessageHandler(p)

		myDID, theirDID, err := h.getDIDs(&transport.Envelope{
			ToKey:   []byte("my_key"),
			FromKey: []byte("their_key"),
		}, nil)

		require.NoError(t, err)
		require.Equal(t, "", myDID)
		require.Equal(t, "", theirDID)
	})

	t.Run("success: theirDID needs retry", func(t *testing.T) {
		p := emptyProvider()
		p.DIDConnectionStoreValue = &mockDIDStore{
			results: map[string]mockDIDResult{
				base58.Encode([]byte("my_key")):    {did: "aaa"},
				base58.Encode([]byte("their_key")): {did: "bbb"},
			},
			temps: map[string]mockDIDResult{
				base58.Encode([]byte("their_key")): {err: didstore.ErrNotFound},
			},
			countDown: 1,
		}
		p.GetDIDsMaxRetriesValue = 3

		h := NewInboundMessageHandler(p)

		myDID, theirDID, err := h.getDIDs(&transport.Envelope{
			ToKey:   []byte("my_key"),
			FromKey: []byte("their_key"),
		}, nil)

		require.NoError(t, err)
		require.Equal(t, "aaa", myDID)
		require.Equal(t, "bbb", theirDID)
	})
}

func emptyProvider() *mockprovider.Provider {
	return &mockprovider.Provider{
		DIDConnectionStoreValue:     &mockDIDStore{},
		MessageServiceProviderValue: &msghandler.MockMsgSvcProvider{},
		InboundMessengerValue:       &mocks.MockMessengerHandler{},
		ServiceValue: &mockdidexchange.MockDIDExchangeSvc{
			AcceptFunc: func(_ string) bool {
				return true
			},
			HandleFunc: func(msg service.DIDCommMsg) (string, error) {
				return "", nil
			},
		},
	}
}

type mockDIDResult struct {
	did string
	err error
}

type mockDIDStore struct {
	getDIDErr error
	results   map[string]mockDIDResult
	temps     map[string]mockDIDResult
	countDown uint
}

// GetDID returns DID associated with key.
func (m *mockDIDStore) GetDID(key string) (string, error) {
	if m.getDIDErr != nil {
		return "", m.getDIDErr
	}

	if m.countDown > 0 {
		m.countDown--

		// note: fallthrough to trying m.results[key] if temps is missing entry
		if res, ok := m.temps[key]; ok {
			return res.did, res.err
		}
	}

	if res, ok := m.results[key]; ok {
		return res.did, res.err
	}

	return "", nil
}

// SaveDID saves DID to the underlying storage.
func (m *mockDIDStore) SaveDID(string, ...string) error {
	return nil
}

// SaveDIDFromDoc saves DID from did.Doc to the underlying storage.
func (m *mockDIDStore) SaveDIDFromDoc(*did.Doc) error {
	return nil
}

// SaveDIDByResolving saves DID resolved by VDR to the underlying storage.
func (m *mockDIDStore) SaveDIDByResolving(string, ...string) error {
	return nil
}
