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

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	mockdidcomm "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	mockwallet "github.com/hyperledger/aries-framework-go/pkg/internal/mock/wallet"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
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
		prov, err := New(WithProtocolServices(&protocol.MockDIDExchangeSvc{
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
		ctx, err := New(WithProtocolServices(&protocol.MockDIDExchangeSvc{
			ProtocolName: "mockProtocolSvc",
			AcceptFunc: func(msgType string) bool {
				return msgType == "valid-message-type"
			},
			HandleFunc: func(msg service.DIDCommMsg) error {
				payload := &struct {
					Label string `json:"label,omitempty"`
				}{}

				err := json.Unmarshal(msg.Payload, payload)
				if err != nil {
					return fmt.Errorf("invalid payload data format: %w", err)
				}

				for _, label := range []string{"Carol"} {
					if label == payload.Label {
						return errors.New("error handling the message")
					}
				}

				return nil
			},
		}))
		require.NoError(t, err)
		require.NotEmpty(t, ctx)

		inboundHandler := ctx.InboundMessageHandler()

		// valid json and message type
		err = inboundHandler(&wallet.Envelope{Message: []byte(`
		{
			"@id": "5678876542345",
			"@type": "valid-message-type"
		}`)})
		require.NoError(t, err)

		// invalid json
		err = inboundHandler(&wallet.Envelope{Message: []byte("invalid json")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid payload data format")

		// invalid json
		err = inboundHandler(&wallet.Envelope{Message: []byte("invalid json")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid payload data format")

		// no handlers
		err = inboundHandler(&wallet.Envelope{Message: []byte(`
		{
			"@type": "invalid-message-type",
			"label": "Bob"
		}`)})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no message handlers found for the message type: invalid-message-type")

		// valid json, message type but service handlers returns error
		err = inboundHandler(&wallet.Envelope{Message: []byte(`
		{
			"label": "Carol",
			"@type": "valid-message-type"
		}`)})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error handling the message")
	})

	t.Run("test new with wallet service", func(t *testing.T) {
		prov, err := New(WithWallet(&mockwallet.CloseableWallet{
			SignMessageValue: []byte("mockValue"), PackValue: []byte("data")}))
		require.NoError(t, err)
		v, err := prov.CryptoWallet().SignMessage(nil, "")
		require.NoError(t, err)
		require.Equal(t, []byte("mockValue"), v)
		v, err = prov.PackWallet().PackMessage(&wallet.Envelope{})
		require.NoError(t, err)
		require.Equal(t, []byte("data"), v)
	})

	t.Run("test new with did wallet service", func(t *testing.T) {
		prov, err := New(WithWallet(&mockwallet.CloseableWallet{SignMessageValue: []byte("mockValue"),
			PackValue: []byte("data"),
			MockDID: &did.Doc{
				Context: []string{"https://w3id.org/did/v1"},
				ID:      "did:example:123456789abcdefghi#inbox"}}),
		)
		require.NoError(t, err)
		v, err := prov.CryptoWallet().SignMessage(nil, "")
		require.NoError(t, err)
		require.Equal(t, []byte("mockValue"), v)
		didDoc, err := prov.DIDWallet().CreateDID("example")
		require.NoError(t, err)
		require.Equal(t, "did:example:123456789abcdefghi#inbox", didDoc.ID)
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

	t.Run("test new with outbound transport service", func(t *testing.T) {
		prov, err := New(WithOutboundTransport(&mockdidcomm.MockOutboundTransport{ExpectedResponse: "data"}))
		require.NoError(t, err)
		r, err := prov.OutboundTransports()[0].Send([]byte("data"), "url")
		require.NoError(t, err)
		require.Equal(t, "data", r)
	})
}
