/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/didrotate"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher/inbound"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	serviceMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/common/service"
	didStoreMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/store/did"
	verifiableStoreMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/store/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockdidcomm "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/msghandler"
	mockpackager "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/packager"
	mockdidexchange "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/generic"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mocklock "github.com/hyperledger/aries-framework-go/pkg/mock/secretlock"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/store/did"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

const validMessageType = "valid-message-type"

func TestNewProvider(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("test new with default", func(t *testing.T) {
		prov, err := New()
		require.NoError(t, err)
		require.Empty(t, prov.OutboundDispatcher())
	})

	t.Run("test new with outbound transport", func(t *testing.T) {
		prov, err := New(WithOutboundDispatcher(&mockdispatcher.MockOutbound{}))
		require.NoError(t, err)
		require.NoError(t, prov.OutboundDispatcher().Send(nil, "", nil))
	})

	t.Run("test new with stores", func(t *testing.T) {
		store := mockstorage.NewMockStoreProvider()

		prov, err := New(WithStorageProvider(store), WithProtocolStateStorageProvider(store))
		require.NoError(t, err)
		require.NotNil(t, prov.ConnectionLookup())
	})

	t.Run("test error return from options", func(t *testing.T) {
		_, err := New(func(opts *Provider) error {
			return errors.New("error creating the framework option")
		})
		require.Error(t, err)
	})

	t.Run("test new with protocol service", func(t *testing.T) {
		prov, err := New(WithProtocolServices(&mockdidexchange.MockDIDExchangeSvc{
			ProtocolName: "mockProtocolSvc",
			AcceptFunc: func(msgType string) bool {
				return msgType == validMessageType
			},
		}))
		require.NoError(t, err)

		_, err = prov.Service("mockProtocolSvc")
		require.NoError(t, err)

		_, err = prov.Service("mockProtocolSvc1")
		require.Error(t, err)
	})

	t.Run("test new with DID connection store", func(t *testing.T) {
		prov, err := New(WithDIDConnectionStore(didStoreMocks.NewMockConnectionStore(ctrl)))
		require.NoError(t, err)
		require.NotNil(t, prov.DIDConnectionStore())
	})

	t.Run("test inbound message handlers/dispatchers", func(t *testing.T) {
		messengerHandler := serviceMocks.NewMockMessengerHandler(ctrl)
		messengerHandler.EXPECT().HandleInbound(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		connectionStore := didStoreMocks.NewMockConnectionStore(ctrl)
		connectionStore.EXPECT().GetDID(gomock.Any()).Return("", nil).AnyTimes()

		ctx, err := New(WithProtocolServices(&mockdidexchange.MockDIDExchangeSvc{
			ProtocolName: "mockProtocolSvc",
			AcceptFunc: func(msgType string) bool {
				return msgType == validMessageType
			},
			HandleFunc: func(msg service.DIDCommMsg) (string, error) {
				payload := &struct {
					Label string `json:"label,omitempty"`
				}{}

				err := msg.Decode(payload)
				if err != nil {
					return "", fmt.Errorf("invalid payload data format: %w", err)
				}

				for _, label := range []string{"Carol"} {
					if label == payload.Label {
						return "", errors.New("error handling the message")
					}
				}

				return uuid.New().String(), nil
			},
		}), WithMessageServiceProvider(msghandler.NewMockMsgServiceProvider()),
			WithMessengerHandler(messengerHandler),
			WithDIDConnectionStore(connectionStore),
			WithInboundEnvelopeHandler(nil))
		require.NoError(t, err)
		require.NotEmpty(t, ctx)

		envHandler := &inbound.MessageHandler{}
		envHandler.Initialize(ctx)
		ctx.inboundEnvelopeHandler = envHandler

		inboundHandler := ctx.InboundMessageHandler()

		// valid json and message type
		err = inboundHandler(&transport.Envelope{Message: []byte(`
		{
			"@frameworkID": "5678876542345",
			"@id":"12345",
			"@type": "valid-message-type"
		}`), ToKey: []byte("toKey"), FromKey: []byte("fromKey")})
		require.NoError(t, err)

		// invalid json
		err = inboundHandler(&transport.Envelope{Message: []byte("invalid json")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid payload data format")

		// no handlers
		err = inboundHandler(&transport.Envelope{Message: []byte(`
		{
			"@type": "invalid-message-type",
			"@id":"12345",
			"label": "Bob"
		}`)})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no message handlers found for the message type: invalid-message-type")

		// valid json, message type but service handlers returns error
		err = inboundHandler(&transport.Envelope{Message: []byte(`
		{
			"label": "Carol",
			"@id":"12345",
			"@type": "valid-message-type"
		}`), ToKey: []byte("toKey"), FromKey: []byte("fromKey")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error handling the message")
	})

	t.Run("test inbound message handlers/dispatchers with ToKey/FromKey as KeyAgreement ID", func(t *testing.T) {
		messengerHandler := serviceMocks.NewMockMessengerHandler(ctrl)
		messengerHandler.EXPECT().HandleInbound(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		connectionStore := didStoreMocks.NewMockConnectionStore(ctrl)

		ctx, err := New(WithProtocolServices(&mockdidexchange.MockDIDExchangeSvc{
			ProtocolName: "mockProtocolSvc",
			AcceptFunc: func(msgType string) bool {
				return msgType == validMessageType
			},
			HandleFunc: func(msg service.DIDCommMsg) (string, error) {
				payload := &struct {
					Label string `json:"label,omitempty"`
				}{}

				err := msg.Decode(payload)
				if err != nil {
					return "", fmt.Errorf("invalid payload data format: %w", err)
				}

				for _, label := range []string{"Carol"} {
					if label == payload.Label {
						return "", errors.New("error handling the message")
					}
				}

				return uuid.New().String(), nil
			},
		}), WithMessageServiceProvider(msghandler.NewMockMsgServiceProvider()),
			WithMessengerHandler(messengerHandler),
			WithDIDConnectionStore(connectionStore))
		require.NoError(t, err)
		require.NotEmpty(t, ctx)

		inboundHandler := ctx.InboundMessageHandler()

		// valid json and message type, ToKey and FromKey are marshalled crypto.PublicKey as per the packers.
		err = inboundHandler(&transport.Envelope{Message: []byte(`
		{
			"@frameworkID": "5678876542345",
			"@id": "12345",
			"@type": "valid-message-type"
		}`), ToKey: []byte("{\"kid\":\"did:peer:bob#key-1\"}"), FromKey: []byte("{\"kid\":\"did:peer:carol#key-1\"}")})
		require.NoError(t, err)

		err = inboundHandler(&transport.Envelope{
			Message: []byte(`{"@type": "valid-message-type", "@id": "12345"}`),
			ToKey:   []byte("{\"kid\":\"did:peer:bob#key-1\""),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "pubKeyToDID")

		err = inboundHandler(&transport.Envelope{
			Message: []byte(`{"@type": "valid-message-type", "@id": "12345"}`),
			ToKey:   []byte("{\"kid\":\"did:peer:bob#key-1\"}"),
			FromKey: []byte("{\"kid\":\"did:peer:carol#key-1\""),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "pubKeyToDID")

		// valid json, message type but service handlers returns error
		err = inboundHandler(&transport.Envelope{Message: []byte(`
		{
			"label": "Carol",
			"@id": "12345",
			"@type": "valid-message-type"
		}`), ToKey: []byte("{\"kid\":\"did:peer:bob#key-1\"}"), FromKey: []byte("{\"kid\":\"did:peer:carol#key-1\"}")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error handling the message")
	})

	t.Run("inbound message handler for didexchange protocol doesn't call GetDID", func(t *testing.T) {
		messengerHandler := serviceMocks.NewMockMessengerHandler(ctrl)
		messengerHandler.EXPECT().
			HandleInbound(gomock.Any(), gomock.Any()).
			Return(nil).
			AnyTimes()

		connectionStore := didStoreMocks.NewMockConnectionStore(ctrl)
		connectionStore.EXPECT().GetDID(gomock.Any()).Return("", nil).Times(0)

		ctx, err := New(WithProtocolServices(&mockdidexchange.MockDIDExchangeSvc{
			ProtocolName: didexchange.DIDExchange,
			AcceptFunc:   func(msgType string) bool { return true },
			HandleFunc:   func(msg service.DIDCommMsg) (string, error) { return uuid.New().String(), nil },
		}), WithMessageServiceProvider(msghandler.NewMockMsgServiceProvider()),
			WithMessengerHandler(messengerHandler),
			WithDIDConnectionStore(connectionStore))
		require.NoError(t, err)
		require.NotEmpty(t, ctx)

		inboundHandler := ctx.InboundMessageHandler()

		err = inboundHandler(&transport.Envelope{Message: []byte(`
		{
			"@frameworkID": "5678876542345",
			"@id": "12345",
			"@type": "valid-message-type"
		}`), FromKey: []byte("fromKey"), ToKey: []byte("toKey")})
		require.NoError(t, err)
	})

	t.Run("inbound message handler: DID not found is ok", func(t *testing.T) {
		messengerHandler := serviceMocks.NewMockMessengerHandler(ctrl)
		messengerHandler.EXPECT().
			HandleInbound(gomock.Any(), gomock.Any()).
			Return(nil).
			AnyTimes()

		connectionStore := didStoreMocks.NewMockConnectionStore(ctrl)
		connectionStore.EXPECT().GetDID(base58.Encode([]byte("toKey"))).Return("", did.ErrNotFound)
		toDIDKey, _ := fingerprint.CreateDIDKey([]byte("toKey"))
		connectionStore.EXPECT().GetDID(toDIDKey).Return("", did.ErrNotFound)
		connectionStore.EXPECT().GetDID(base58.Encode([]byte("toKey"))).Return("", did.ErrNotFound)
		connectionStore.EXPECT().GetDID(toDIDKey).Return("", did.ErrNotFound)
		connectionStore.EXPECT().GetDID(base58.Encode([]byte("fromKey"))).Return("", errors.New("error"))
		fromDIDKey, _ := fingerprint.CreateDIDKey([]byte("fromKey"))
		connectionStore.EXPECT().GetDID(base58.Encode([]byte("fromKey"))).Return("", did.ErrNotFound)
		connectionStore.EXPECT().GetDID(fromDIDKey).Return("", did.ErrNotFound)

		ctx, err := New(WithProtocolServices(&mockdidexchange.MockDIDExchangeSvc{
			ProtocolName: "mockProtocolSvc",
			AcceptFunc:   func(msgType string) bool { return true },
			HandleFunc:   func(msg service.DIDCommMsg) (string, error) { return uuid.New().String(), nil },
		}), WithMessageServiceProvider(msghandler.NewMockMsgServiceProvider()),
			WithMessengerHandler(messengerHandler),
			WithDIDConnectionStore(connectionStore),
			WithGetDIDsMaxRetries(1),
			WithGetDIDsBackOffDuration(time.Millisecond))
		require.NoError(t, err)
		require.NotEmpty(t, ctx)

		inboundHandler := ctx.InboundMessageHandler()

		err = inboundHandler(&transport.Envelope{Message: []byte(`
		{
			"@frameworkID": "5678876542345",
			"@id": "12345",
			"@type": "valid-message-type"
		}`), FromKey: []byte("fromKey"), ToKey: []byte("toKey")})
		require.NoError(t, err)
	})

	t.Run("inbound message handler: failed to get my did", func(t *testing.T) {
		messengerHandler := serviceMocks.NewMockMessengerHandler(ctrl)
		messengerHandler.EXPECT().
			HandleInbound(gomock.Any(), gomock.Any()).
			Return(nil).
			AnyTimes()

		connectionStore := didStoreMocks.NewMockConnectionStore(ctrl)
		connectionStore.EXPECT().
			GetDID(base58.Encode([]byte("toKey"))).
			Return("", errors.New("get DID error")).
			AnyTimes()

		connectionStore.EXPECT().
			GetDID(base58.Encode([]byte("fromKey"))).
			Return("", nil).
			AnyTimes()

		ctx, err := New(WithProtocolServices(&mockdidexchange.MockDIDExchangeSvc{
			ProtocolName: "mockProtocolSvc",
			AcceptFunc:   func(msgType string) bool { return true },
			HandleFunc:   func(msg service.DIDCommMsg) (string, error) { return uuid.New().String(), nil },
		}), WithMessageServiceProvider(msghandler.NewMockMsgServiceProvider()),
			WithMessengerHandler(messengerHandler),
			WithDIDConnectionStore(connectionStore))
		require.NoError(t, err)
		require.NotEmpty(t, ctx)

		inboundHandler := ctx.InboundMessageHandler()

		err = inboundHandler(&transport.Envelope{Message: []byte(`
		{
			"@frameworkID": "5678876542345",
			"@id": "12345",
			"@type": "valid-message-type"
		}`), FromKey: []byte("fromKey"), ToKey: []byte("toKey")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get my did")
	})

	t.Run("inbound message handler: failed to get my did from didKey", func(t *testing.T) {
		messengerHandler := serviceMocks.NewMockMessengerHandler(ctrl)
		messengerHandler.EXPECT().
			HandleInbound(gomock.Any(), gomock.Any()).
			Return(nil).
			AnyTimes()

		connectionStore := didStoreMocks.NewMockConnectionStore(ctrl)

		// first call
		connectionStore.EXPECT().GetDID(base58.Encode([]byte("toKey"))).Return("", did.ErrNotFound)
		toDIDKey, _ := fingerprint.CreateDIDKey([]byte("toKey"))
		connectionStore.EXPECT().
			GetDID(toDIDKey).
			Return("", errors.New("get DID error")).
			AnyTimes()

		// second call due to maxRetries = 1
		connectionStore.EXPECT().GetDID(base58.Encode([]byte("toKey"))).Return("", did.ErrNotFound)
		connectionStore.EXPECT().
			GetDID(toDIDKey).
			Return("", errors.New("get DID error")).
			AnyTimes()

		ctx, err := New(WithProtocolServices(&mockdidexchange.MockDIDExchangeSvc{
			ProtocolName: "mockProtocolSvc",
			AcceptFunc:   func(msgType string) bool { return true },
			HandleFunc:   func(msg service.DIDCommMsg) (string, error) { return uuid.New().String(), nil },
		}), WithMessageServiceProvider(msghandler.NewMockMsgServiceProvider()),
			WithMessengerHandler(messengerHandler),
			WithDIDConnectionStore(connectionStore),
			WithGetDIDsMaxRetries(1),
			WithGetDIDsBackOffDuration(time.Millisecond))
		require.NoError(t, err)
		require.NotEmpty(t, ctx)

		inboundHandler := ctx.InboundMessageHandler()

		err = inboundHandler(&transport.Envelope{Message: []byte(`
		{
			"@frameworkID": "5678876542345",
			"@id": "12345",
			"@type": "valid-message-type"
		}`), FromKey: []byte("fromKey"), ToKey: []byte("toKey")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get my did")
	})

	t.Run("inbound message handler: failed to get their did", func(t *testing.T) {
		messengerHandler := serviceMocks.NewMockMessengerHandler(ctrl)
		messengerHandler.EXPECT().
			HandleInbound(gomock.Any(), gomock.Any()).
			Return(nil).
			AnyTimes()

		connectionStore := didStoreMocks.NewMockConnectionStore(ctrl)
		connectionStore.EXPECT().
			GetDID(base58.Encode([]byte("toKey"))).
			Return("", nil).
			AnyTimes()

		connectionStore.EXPECT().
			GetDID(base58.Encode([]byte("fromKey"))).
			Return("", errors.New("get DID error")).
			AnyTimes()

		ctx, err := New(WithProtocolServices(&mockdidexchange.MockDIDExchangeSvc{
			ProtocolName: "mockProtocolSvc",
			AcceptFunc:   func(msgType string) bool { return true },
			HandleFunc:   func(msg service.DIDCommMsg) (string, error) { return uuid.New().String(), nil },
		}), WithMessageServiceProvider(msghandler.NewMockMsgServiceProvider()),
			WithMessengerHandler(messengerHandler),
			WithDIDConnectionStore(connectionStore))
		require.NoError(t, err)
		require.NotEmpty(t, ctx)

		inboundHandler := ctx.InboundMessageHandler()

		err = inboundHandler(&transport.Envelope{Message: []byte(`
		{
			"@frameworkID": "5678876542345",
			"@id": "12345",
			"@type": "valid-message-type"
		}`), FromKey: []byte("fromKey"), ToKey: []byte("toKey")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get their did")
	})

	t.Run("inbound message handler: failed to get their did from didKey", func(t *testing.T) {
		messengerHandler := serviceMocks.NewMockMessengerHandler(ctrl)
		messengerHandler.EXPECT().
			HandleInbound(gomock.Any(), gomock.Any()).
			Return(nil).
			AnyTimes()

		connectionStore := didStoreMocks.NewMockConnectionStore(ctrl)
		// first try
		connectionStore.EXPECT().GetDID(base58.Encode([]byte("toKey"))).Return("", did.ErrNotFound)
		toDIDKey, _ := fingerprint.CreateDIDKey([]byte("toKey"))
		connectionStore.EXPECT().GetDID(toDIDKey).Return("", did.ErrNotFound)
		connectionStore.EXPECT().GetDID(base58.Encode([]byte("fromKey"))).Return("", did.ErrNotFound)
		fromDIDKey, _ := fingerprint.CreateDIDKey([]byte("fromKey"))
		connectionStore.EXPECT().
			GetDID(fromDIDKey).
			Return("", errors.New("get DID error")).
			AnyTimes()

		// second try since first try returns error and maxRetries = 1
		connectionStore.EXPECT().GetDID(base58.Encode([]byte("toKey"))).Return("", did.ErrNotFound)
		connectionStore.EXPECT().GetDID(toDIDKey).Return("", did.ErrNotFound)
		connectionStore.EXPECT().GetDID(base58.Encode([]byte("fromKey"))).Return("", did.ErrNotFound)
		connectionStore.EXPECT().
			GetDID(fromDIDKey).
			Return("", errors.New("get DID error")).
			AnyTimes()

		ctx, err := New(WithProtocolServices(&mockdidexchange.MockDIDExchangeSvc{
			ProtocolName: "mockProtocolSvc",
			AcceptFunc:   func(msgType string) bool { return true },
			HandleFunc:   func(msg service.DIDCommMsg) (string, error) { return uuid.New().String(), nil },
		}), WithMessageServiceProvider(msghandler.NewMockMsgServiceProvider()),
			WithMessengerHandler(messengerHandler),
			WithDIDConnectionStore(connectionStore),
			WithGetDIDsMaxRetries(1),
			WithGetDIDsBackOffDuration(time.Millisecond))
		require.NoError(t, err)
		require.NotEmpty(t, ctx)

		inboundHandler := ctx.InboundMessageHandler()

		err = inboundHandler(&transport.Envelope{Message: []byte(`
		{
			"@frameworkID": "5678876542345",
			"@id": "12345",
			"@type": "valid-message-type"
		}`), FromKey: []byte("fromKey"), ToKey: []byte("toKey")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get their did")
	})

	t.Run("generic message handler: failed to get did", func(t *testing.T) {
		messengerHandler := serviceMocks.NewMockMessengerHandler(ctrl)
		messengerHandler.EXPECT().
			HandleInbound(gomock.Any(), gomock.Any()).
			Return(nil).
			AnyTimes()

		mockMsgHandler := msghandler.NewMockMsgServiceProvider()

		connectionStore := didStoreMocks.NewMockConnectionStore(ctrl)
		connectionStore.EXPECT().GetDID(gomock.Any()).Return("", errors.New("get DID error")).AnyTimes()

		ctx, err := New(
			WithMessageServiceProvider(mockMsgHandler),
			WithMessengerHandler(messengerHandler),
			WithDIDConnectionStore(connectionStore),
		)
		require.NoError(t, err)
		require.NotEmpty(t, ctx)
		require.NotEmpty(t, ctx.Messenger())

		require.NoError(t, mockMsgHandler.Register(&generic.MockMessageSvc{}))

		inboundHandler := ctx.InboundMessageHandler()

		// valid json and message type
		err = inboundHandler(&transport.Envelope{Message: []byte(`
		{
			"@frameworkID": "5678876542345",
			"@id": "12345",
			"@type": "valid-message-type"
		}`), ToKey: []byte("toKey"), FromKey: []byte("fromKey")})

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get my did")
	})

	t.Run("messenger handle inbound error", func(t *testing.T) {
		errTest := errors.New("test")

		messengerHandler := serviceMocks.NewMockMessengerHandler(ctrl)
		messengerHandler.EXPECT().
			HandleInbound(gomock.Any(), gomock.Any()).
			Return(errTest).
			Times(1)

		mockMsgHandler := msghandler.NewMockMsgServiceProvider()

		connectionStore := didStoreMocks.NewMockConnectionStore(ctrl)
		connectionStore.EXPECT().GetDID(gomock.Any()).Return("", nil).AnyTimes()

		ctx, err := New(
			WithMessageServiceProvider(mockMsgHandler),
			WithMessengerHandler(messengerHandler),
			WithDIDConnectionStore(connectionStore),
		)
		require.NoError(t, err)
		require.NotEmpty(t, ctx)
		require.NotEmpty(t, ctx.Messenger())

		require.NoError(t, mockMsgHandler.Register(&generic.MockMessageSvc{}))

		inboundHandler := ctx.InboundMessageHandler()

		// valid json and message type
		err = inboundHandler(&transport.Envelope{Message: []byte(`
		{
			"@frameworkID": "5678876542345",
			"@id": "12345",
			"@type": "valid-message-type"
		}`), ToKey: []byte("toKey"), FromKey: []byte("fromKey")})

		require.EqualError(t, errors.Unwrap(err), errTest.Error())
	})

	t.Run("InboundDIDCommMsgHandler", func(t *testing.T) {
		expected := service.NewDIDCommMsgMap(&didexchange.Request{
			Type: "test-type",
		})
		expectedMyDID := "123"
		expectedTheirDID := "456"
		handled := false
		accepted := false
		ctx, err := New(WithProtocolServices(&mockdidexchange.MockDIDExchangeSvc{
			HandleFunc: func(result service.DIDCommMsg) (string, error) {
				handled = true
				require.Equal(t, expected, result)
				return "", nil
			},
			AcceptFunc: func(msgType string) bool {
				accepted = true
				require.Equal(t, expected.Type(), msgType)
				return true
			},
		}))
		require.NoError(t, err)
		handler := ctx.InboundDIDCommMessageHandler()
		require.NotNil(t, handler)
		_, err = handler().HandleInbound(expected, service.NewDIDCommContext(expectedMyDID, expectedTheirDID, nil))
		require.NoError(t, err)
		require.True(t, accepted)
		require.True(t, handled)
	})

	t.Run("InboundDIDCommMsgHandler fails if msg not handled", func(t *testing.T) {
		ctx, err := New(WithProtocolServices(&mockdidexchange.MockDIDExchangeSvc{
			AcceptFunc: func(msgType string) bool {
				return false
			},
		}))
		require.NoError(t, err)
		_, err = ctx.InboundDIDCommMessageHandler()().HandleInbound(service.NewDIDCommMsgMap(&didexchange.Request{
			Type: "test",
		}), service.EmptyDIDCommContext())
		require.Error(t, err)
	})

	t.Run("test new with message service", func(t *testing.T) {
		const sampleMsgType = "generic-msg-type-2.0"

		handled := make(chan bool, 1)

		messenger := serviceMocks.NewMockMessengerHandler(ctrl)
		messenger.EXPECT().
			HandleInbound(gomock.Any(), gomock.Any()).
			Return(nil).
			AnyTimes()

		mockMsgHandler := msghandler.NewMockMsgServiceProvider()

		connectionStore := didStoreMocks.NewMockConnectionStore(ctrl)
		connectionStore.EXPECT().GetDID(gomock.Any()).Return("", nil).AnyTimes()

		prov, err := New(WithMessageServiceProvider(mockMsgHandler), WithMessengerHandler(messenger),
			WithDIDConnectionStore(connectionStore))
		require.NoError(t, err)

		err = mockMsgHandler.Register(&generic.MockMessageSvc{
			HandleFunc: func(*service.DIDCommMsg) (string, error) {
				handled <- true
				return "", nil
			},
			AcceptFunc: func(msgType string, purpose []string) bool {
				return sampleMsgType == msgType
			},
		})
		require.NoError(t, err)

		inboundHandler := prov.InboundMessageHandler()

		err = inboundHandler(&transport.Envelope{Message: []byte(fmt.Sprintf(`
		{
			"@frameworkID": "5678876542345",
			"@id": "12345",
			"@type": "%s"
		}`, sampleMsgType)), ToKey: []byte("toKey"), FromKey: []byte("fromKey")})
		require.NoError(t, err)

		select {
		case h := <-handled:
			require.True(t, h)
		case <-time.After(5 * time.Second):
			require.Fail(t, "generic service handler not called")
		}
	})

	t.Run("test new with crypto, KMS, packer and packager services", func(t *testing.T) {
		prov, err := New(
			WithKMS(&mockkms.KeyManager{CreateKeyID: "123"}),
			WithCrypto(&mockcrypto.Crypto{SignValue: []byte("mockValue")}),
			WithPackager(&mockpackager.Packager{PackValue: []byte("data")}),
			WithPacker(
				&mockdidcomm.MockAuthCrypt{
					EncryptValue: func(cty string, p, spk []byte, rpks [][]byte) ([]byte, error) {
						return []byte("data data"), nil
					},
					DecryptValue: nil,
					Type:         "",
				},
				&mockdidcomm.MockAuthCrypt{
					EncryptValue: nil,
					DecryptValue: nil,
					Type:         "TYPE",
				}),
		)
		require.NoError(t, err)
		v, err := prov.Crypto().Sign(nil, "")
		require.NoError(t, err)
		require.Equal(t, []byte("mockValue"), v)
		v, err = prov.Packager().PackMessage(&transport.Envelope{})
		require.NoError(t, err)
		require.Equal(t, []byte("data"), v)

		v, err = prov.PrimaryPacker().Pack("", nil, nil, nil)
		require.NoError(t, err)
		require.Equal(t, []byte("data data"), v)

		packers := prov.Packers()
		require.Len(t, packers, 1)
		typ := packers[0].EncodingType()
		require.Equal(t, "TYPE", typ)
	})

	t.Run("test new with crypto service", func(t *testing.T) {
		mCrypto := &mockcrypto.Crypto{}
		prov, err := New(WithCrypto(mCrypto))
		require.NoError(t, err)
		require.Equal(t, mCrypto, prov.Crypto())
	})

	t.Run("test new with did rotator service", func(t *testing.T) {
		didRotator := &didrotate.DIDRotator{}
		prov, err := New(WithDIDRotator(didRotator))
		require.NoError(t, err)
		require.Equal(t, didRotator, prov.DIDRotator())
	})

	t.Run("test new with secret lock service", func(t *testing.T) {
		mSecLck := &mocklock.MockSecretLock{}
		prov, err := New(WithSecretLock(mSecLck))
		require.NoError(t, err)
		require.Equal(t, mSecLck, prov.SecretLock())
	})

	t.Run("test new with kms service", func(t *testing.T) {
		mKMS := &mockkms.KeyManager{}
		prov, err := New(WithKMS(mKMS))
		require.NoError(t, err)
		require.Equal(t, mKMS, prov.KMS())
	})

	t.Run("test new with inbound transport endpoint", func(t *testing.T) {
		prov, err := New(WithServiceEndpoint("endpoint"))
		require.NoError(t, err)
		require.Equal(t, "endpoint", prov.ServiceEndpoint())
	})

	t.Run("test new with router endpoint", func(t *testing.T) {
		prov, err := New(WithRouterEndpoint("router-endpoint"))
		require.NoError(t, err)
		require.Equal(t, "router-endpoint", prov.RouterEndpoint())
	})

	t.Run("test new with storage provider", func(t *testing.T) {
		s := mockstorage.NewMockStoreProvider()
		prov, err := New(WithStorageProvider(s))
		require.NoError(t, err)
		require.Equal(t, s, prov.StorageProvider())
	})

	t.Run("test new with protocol state storage provider", func(t *testing.T) {
		s := mockstorage.NewMockStoreProvider()
		prov, err := New(WithProtocolStateStorageProvider(s))
		require.NoError(t, err)
		require.Equal(t, s, prov.ProtocolStateStorageProvider())
	})

	t.Run("test new with vdr", func(t *testing.T) {
		r := &mockvdr.MockVDRegistry{}
		prov, err := New(WithVDRegistry(r))
		require.NoError(t, err)
		require.Equal(t, r, prov.VDRegistry())
	})

	t.Run("test new with outbound transport service", func(t *testing.T) {
		prov, err := New(WithOutboundTransports(&mockdidcomm.MockOutboundTransport{ExpectedResponse: "data"},
			&mockdidcomm.MockOutboundTransport{ExpectedResponse: "data1"}))
		require.NoError(t, err)
		require.Len(t, prov.OutboundTransports(), 2)
		r, err := prov.outboundTransports[0].Send([]byte("data"), &service.Destination{ServiceEndpoint: "url"})
		require.NoError(t, err)
		require.Equal(t, "data", r)
		r, err = prov.outboundTransports[1].Send([]byte("data1"), &service.Destination{ServiceEndpoint: "url"})
		require.NoError(t, err)
		require.Equal(t, "data1", r)
	})

	t.Run("test new with transport return route", func(t *testing.T) {
		transportReturnRoute := "none"
		prov, err := New(WithTransportReturnRoute(transportReturnRoute))
		require.NoError(t, err)
		require.Equal(t, transportReturnRoute, prov.TransportReturnRoute())
	})

	t.Run("test new with verifiable store", func(t *testing.T) {
		verifiableStore := verifiableStoreMocks.NewMockStore(ctrl)
		prov, err := New(WithVerifiableStore(verifiableStore))
		require.NoError(t, err)
		require.Equal(t, verifiableStore, prov.VerifiableStore())
	})

	t.Run("test new with JSON-LD document loader", func(t *testing.T) {
		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		prov, err := New(WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)
		require.Equal(t, loader, prov.JSONLDDocumentLoader())
	})

	t.Run("test new with bad (fake) option", func(t *testing.T) {
		prov, err := New(func(opts *Provider) error {
			return fmt.Errorf("bad option")
		})
		require.EqualError(t, err, "option failed: bad option")
		require.Empty(t, prov)
	})

	t.Run("test new with framework ID", func(t *testing.T) {
		frameworkID := "none"
		prov, err := New(WithAriesFrameworkID(frameworkID))
		require.NoError(t, err)
		require.Equal(t, frameworkID, prov.AriesFrameworkID())
	})

	t.Run("test new with KeyType", func(t *testing.T) {
		prov, err := New(WithKeyType(kms.ECDSAP256TypeIEEEP1363))
		require.NoError(t, err)
		require.EqualValues(t, kms.ECDSAP256TypeIEEEP1363, prov.KeyType())

		_, err = New(WithKeyType(kms.XChaCha20Poly1305Type))
		require.EqualError(t, err, "option failed: invalid authentication key type: XChaCha20Poly1305")
	})

	t.Run("test new with KeyType for KeyAgreement", func(t *testing.T) {
		prov, err := New(WithKeyAgreementType(kms.NISTP256ECDHKWType))
		require.NoError(t, err)
		require.Equal(t, kms.NISTP256ECDHKWType, prov.KeyAgreementType())

		_, err = New(WithKeyAgreementType(kms.XChaCha20Poly1305Type))
		require.EqualError(t, err, "option failed: invalid KeyAgreement key type: XChaCha20Poly1305")
	})

	t.Run("test new with mediaTypeProfiles", func(t *testing.T) {
		prov, err := New(WithMediaTypeProfiles([]string{
			transport.MediaTypeV2EncryptedEnvelope,
			transport.MediaTypeV1EncryptedEnvelope,
			transport.MediaTypeRFC0019EncryptedEnvelope,
		}))
		require.NoError(t, err)
		require.Equal(t, 3, len(prov.MediaTypeProfiles()))
		require.Equal(t, transport.MediaTypeV2EncryptedEnvelope, prov.MediaTypeProfiles()[0])
		require.Equal(t, transport.MediaTypeV1EncryptedEnvelope, prov.MediaTypeProfiles()[1])
		require.Equal(t, transport.MediaTypeRFC0019EncryptedEnvelope, prov.MediaTypeProfiles()[2])
	})
}
