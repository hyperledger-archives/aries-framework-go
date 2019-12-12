/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/internal/mock/crypto"
	mockdidcomm "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/dispatcher"
	mockpackager "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/packager"
	mockdidexchange "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol/generic"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/internal/mock/kms"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/internal/mock/vdri"
)

func TestNewProvider(t *testing.T) {
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
		ctx, err := New(WithProtocolServices(&mockdidexchange.MockDIDExchangeSvc{
			ProtocolName: "mockProtocolSvc",
			AcceptFunc: func(msgType string) bool {
				return msgType == "valid-message-type"
			},
			HandleFunc: func(msg *service.DIDCommMsg) (string, error) {
				payload := &struct {
					Label string `json:"label,omitempty"`
				}{}

				err := json.Unmarshal(msg.Payload, payload)
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
		}))
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

	t.Run("test new with generic inbound service", func(t *testing.T) {
		const sampleMsgType = "generic-msg-type-2.0"

		handled := make(chan bool, 1)
		prov, err := New(WithMessageServices(&generic.MockGenericSvc{
			HandleFunc: func(*service.DIDCommMsg) (string, error) {
				handled <- true
				return "", nil
			},
			AcceptFunc: func(header *service.Header) bool {
				return header.Type == sampleMsgType
			},
		}))
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

	t.Run("test new with kms and packager service", func(t *testing.T) {
		prov, err := New(
			WithKMS(&mockkms.CloseableKMS{SignMessageValue: []byte("mockValue")}),
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
		v, err := prov.Signer().SignMessage(nil, "")
		require.NoError(t, err)
		require.Equal(t, []byte("mockValue"), v)
		index, err := prov.KMS().FindVerKey([]string{"non-existent"})
		require.NoError(t, err)
		require.Equal(t, 0, index)
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

	t.Run("test new with inbound transport endpoint", func(t *testing.T) {
		prov, err := New(WithInboundTransportEndpoint("endpoint"))
		require.NoError(t, err)
		require.Equal(t, "endpoint", prov.InboundTransportEndpoint())
	})

	t.Run("test new with storage provider", func(t *testing.T) {
		s := storage.NewMockStoreProvider()
		prov, err := New(WithStorageProvider(s))
		require.NoError(t, err)
		require.Equal(t, s, prov.StorageProvider())
	})

	t.Run("test new with transient storage provider", func(t *testing.T) {
		s := storage.NewMockStoreProvider()
		prov, err := New(WithTransientStorageProvider(s))
		require.NoError(t, err)
		require.Equal(t, s, prov.TransientStorageProvider())
	})

	t.Run("test new with vdri", func(t *testing.T) {
		r := &mockvdri.MockVDRIRegistry{}
		prov, err := New(WithVDRIRegistry(r))
		require.NoError(t, err)
		require.Equal(t, r, prov.VDRIRegistry())
	})

	t.Run("test new with outbound transport service", func(t *testing.T) {
		prov, err := New(WithOutboundTransports(&mockdidcomm.MockOutboundTransport{ExpectedResponse: "data"},
			&mockdidcomm.MockOutboundTransport{ExpectedResponse: "data1"}))
		require.NoError(t, err)
		require.Equal(t, 2, len(prov.OutboundTransports()))
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

	t.Run("test new with framework id", func(t *testing.T) {
		frameworkID := "aries-framework-1"
		prov, err := New(WithAriesFrameworkID(frameworkID))
		require.NoError(t, err)
		require.Equal(t, frameworkID, prov.AriesFrameworkID())
	})
}
