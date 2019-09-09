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

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/wallet"
)

func TestNewProvider(t *testing.T) {
	t.Run("test new with default", func(t *testing.T) {
		prov, err := New()
		require.NoError(t, err)
		require.Empty(t, prov.OutboundTransport())
	})

	t.Run("test new with outbound transport", func(t *testing.T) {
		prov, err := New(WithOutboundTransport(didcomm.NewMockOutboundTransport("success")))
		require.NoError(t, err)
		require.NotEmpty(t, prov.OutboundTransport())
	})

	t.Run("test error return from options", func(t *testing.T) {
		_, err := New(func(opts *Provider) error {
			return errors.New("error creating the framework option")
		})
		require.Error(t, err)
	})

	t.Run("test new with protocol service", func(t *testing.T) {
		prov, err := New(WithProtocolServices(mockProtocolSvc{}))
		require.NoError(t, err)

		_, err = prov.Service("mockProtocolSvc")
		require.NoError(t, err)

		_, err = prov.Service("mockProtocolSvc1")
		require.Error(t, err)

	})

	t.Run("test inbound message handlers/dispatchers", func(t *testing.T) {
		ctx, err := New(WithProtocolServices(mockProtocolSvc{rejectLabels: []string{"Carol"}}))
		require.NoError(t, err)
		require.NotEmpty(t, ctx)

		inboundHandler := ctx.InboundMessageHandler()

		// valid json and message type
		err = inboundHandler([]byte(`
		{
			"@id": "5678876542345",
			"@type": "valid-message-type"
		}`))
		require.NoError(t, err)

		// invalid json
		err = inboundHandler([]byte("invalid json"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid payload data format")

		// invalid json
		err = inboundHandler([]byte("invalid json"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid payload data format")

		// no handlers
		err = inboundHandler([]byte(`
		{
			"@type": "invalid-message-type",
			"label": "Bob"
		}`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "no message handlers found for the message type: invalid-message-type")

		// valid json, message type but service handlers returns error
		err = inboundHandler([]byte(`
		{
			"label": "Carol",
			"@type": "valid-message-type"
		}`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "error handling the message")
	})

	t.Run("test new with wallet service", func(t *testing.T) {
		prov, err := New(WithWallet(&wallet.CloseableWallet{SignMessageValue: []byte("mockValue")}))
		require.NoError(t, err)
		v, err := prov.CryptoWallet().SignMessage(nil, "")
		require.NoError(t, err)
		require.Equal(t, []byte("mockValue"), v)
	})
}

type mockProtocolSvc struct {
	rejectLabels []string
}

func (m mockProtocolSvc) Handle(msg dispatcher.DIDCommMsg) error {
	payload := &struct {
		Label string `json:"label,omitempty"`
	}{}

	err := json.Unmarshal(msg.Payload, payload)
	if err != nil {
		return fmt.Errorf("invalid payload data format: %w", err)
	}

	for _, label := range m.rejectLabels {
		if label == payload.Label {
			return errors.New("error handling the message")
		}
	}

	return nil
}

func (m mockProtocolSvc) Accept(msgType string) bool {
	return msgType == "valid-message-type"
}

func (m mockProtocolSvc) Name() string {
	return "mockProtocolSvc"
}
