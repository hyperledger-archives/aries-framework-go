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

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	serviceMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/common/service"
	verifiableStoreMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/store/verifiable"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockdidcomm "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/msghandler"
	mockpackager "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/packager"
	mockdidexchange "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/generic"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mocklock "github.com/hyperledger/aries-framework-go/pkg/mock/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
)

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
				return msgType == "valid-message-type"
			},
		}))
		require.NoError(t, err)

		_, err = prov.Service("mockProtocolSvc")
		require.NoError(t, err)

		_, err = prov.Service("mockProtocolSvc1")
		require.Error(t, err)
	})

	t.Run("test inbound message handlers/dispatchers", func(t *testing.T) {
		messengerHandler := serviceMocks.NewMockMessengerHandler(ctrl)
		messengerHandler.EXPECT().HandleInbound(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		ctx, err := New(WithProtocolServices(&mockdidexchange.MockDIDExchangeSvc{
			ProtocolName: "mockProtocolSvc",
			AcceptFunc: func(msgType string) bool {
				return msgType == "valid-message-type"
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
		}), WithMessageServiceProvider(msghandler.NewMockMsgServiceProvider()), WithMessengerHandler(messengerHandler))
		require.NoError(t, err)
		require.NotEmpty(t, ctx)

		inboundHandler := ctx.InboundMessageHandler()

		// valid json and message type
		err = inboundHandler([]byte(`
		{
			"@frameworkID": "5678876542345",
			"@type": "valid-message-type"
		}`), "", "")
		require.NoError(t, err)

		// invalid json
		err = inboundHandler([]byte("invalid json"), "", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid payload data format")

		// invalid json
		err = inboundHandler([]byte("invalid json"), "", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid payload data format")

		// no handlers
		err = inboundHandler([]byte(`
		{
			"@type": "invalid-message-type",
			"label": "Bob"
		}`), "", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "no message handlers found for the message type: invalid-message-type")

		// valid json, message type but service handlers returns error
		err = inboundHandler([]byte(`
		{
			"label": "Carol",
			"@type": "valid-message-type"
		}`), "", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error handling the message")
	})

	t.Run("Messenger handle inbound error", func(t *testing.T) {
		errTest := errors.New("test")

		messengerHandler := serviceMocks.NewMockMessengerHandler(ctrl)
		messengerHandler.EXPECT().
			HandleInbound(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(errTest).
			Times(1)

		mockMsgHandler := msghandler.NewMockMsgServiceProvider()

		ctx, err := New(
			WithMessageServiceProvider(mockMsgHandler),
			WithMessengerHandler(messengerHandler),
		)
		require.NoError(t, err)
		require.NotEmpty(t, ctx)
		require.NotEmpty(t, ctx.Messenger())

		require.NoError(t, mockMsgHandler.Register(&generic.MockMessageSvc{}))

		inboundHandler := ctx.InboundMessageHandler()

		// valid json and message type
		err = inboundHandler([]byte(`
		{
			"@frameworkID": "5678876542345",
			"@type": "valid-message-type"
		}`), "", "")

		require.EqualError(t, errors.Unwrap(err), errTest.Error())
	})

	t.Run("outbound message handler", func(t *testing.T) {
		expected := service.NewDIDCommMsgMap(&didexchange.Request{
			Type: "test-type",
		})
		expectedMyDID := "123"
		expectedTheirDID := "456"
		handled := false
		accepted := false
		ctx, err := New(WithProtocolServices(&mockdidexchange.MockDIDExchangeSvc{
			HandleOutboundFunc: func(result service.DIDCommMsg, myDID, theirDID string) (string, error) {
				handled = true
				require.Equal(t, expected, result)
				require.Equal(t, expectedMyDID, myDID)
				require.Equal(t, expectedTheirDID, theirDID)
				return "", nil
			},
			AcceptFunc: func(msgType string) bool {
				accepted = true
				require.Equal(t, expected.Type(), msgType)
				return true
			},
		}))
		require.NoError(t, err)
		handler := ctx.OutboundMessageHandler()
		require.NotNil(t, handler)
		_, err = handler.HandleOutbound(expected, expectedMyDID, expectedTheirDID)
		require.NoError(t, err)
		require.True(t, accepted)
		require.True(t, handled)
	})

	t.Run("outbound message handler fails if msg not handles", func(t *testing.T) {
		ctx, err := New(WithProtocolServices(&mockdidexchange.MockDIDExchangeSvc{
			AcceptFunc: func(msgType string) bool {
				return false
			},
		}))
		require.NoError(t, err)
		_, err = ctx.OutboundMessageHandler().HandleOutbound(service.NewDIDCommMsgMap(&didexchange.Request{
			Type: "test",
		}), "myDID", "theirDID")
		require.Error(t, err)
	})

	t.Run("test new with message service", func(t *testing.T) {
		const sampleMsgType = "generic-msg-type-2.0"

		handled := make(chan bool, 1)

		messenger := serviceMocks.NewMockMessengerHandler(ctrl)
		messenger.EXPECT().
			HandleInbound(gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil).
			AnyTimes()

		mockMsgHandler := msghandler.NewMockMsgServiceProvider()
		prov, err := New(WithMessageServiceProvider(mockMsgHandler), WithMessengerHandler(messenger))
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

		err = inboundHandler([]byte(fmt.Sprintf(`
		{
			"@frameworkID": "5678876542345",
			"@type": "%s"
		}`, sampleMsgType)), "did1", "did2")
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
					EncryptValue: func(p, spk []byte, rpks [][]byte) ([]byte, error) {
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

		v, err = prov.PrimaryPacker().Pack(nil, nil, nil)
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
		s := storage.NewMockStoreProvider()
		prov, err := New(WithStorageProvider(s))
		require.NoError(t, err)
		require.Equal(t, s, prov.StorageProvider())
	})

	t.Run("test new with protocol state storage provider", func(t *testing.T) {
		s := storage.NewMockStoreProvider()
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
}
