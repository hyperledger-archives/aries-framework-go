/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"bytes"
	"encoding/json"
	"testing"

	config2 "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/config"

	"github.com/hyperledger/aries-framework-go/pkg/config"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	mocktransport "github.com/hyperledger/aries-framework-go/pkg/internal/didcomm/transport/mock"
	"github.com/stretchr/testify/require"
	errors "golang.org/x/xerrors"
)

var configYAML = `
aries:
  agent:
    label: agent
    serviceEndpoint: https://example.com/endpoint
`

func TestNewProvider(t *testing.T) {
	t.Run("test new with default", func(t *testing.T) {
		prov, err := New()
		require.NoError(t, err)
		require.Empty(t, prov.OutboundTransport())
	})
	t.Run("test new with outbound transport", func(t *testing.T) {
		prov, err := New(WithOutboundTransport(mocktransport.NewOutboundTransport("success")))
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
		mockSvcCreator := func(prv api.Provider) (dispatcher.Service, error) {
			return mockProtocolSvc{}, nil
		}
		prov, err := New(WithProtocols(mockSvcCreator))
		require.NoError(t, err)

		_, err = prov.Service("mockProtocolSvc")
		require.NoError(t, err)

		_, err = prov.Service("mockProtocolSvc1")
		require.Error(t, err)

	})

	t.Run("test error from protocol service", func(t *testing.T) {
		newMockSvc := func(prv api.Provider) (dispatcher.Service, error) {
			return nil, errors.New("error creating the protocol")
		}
		_, err := New(WithProtocols(newMockSvc))
		require.Error(t, err)
		require.Contains(t, err.Error(), "error creating the protocol")
	})

	t.Run("test inbound message handlers/dispatchers", func(t *testing.T) {
		newMockSvc := func(prv api.Provider) (dispatcher.Service, error) {
			return mockProtocolSvc{rejectLabels: []string{"Carol"}}, nil
		}
		ctx, err := New(WithProtocols(newMockSvc))
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

	t.Run("test new with protocol service", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte(configYAML))
		configBackend, err := config.FromReader(buf, "yaml")()
		require.NoError(t, err)
		c := config2.FromBackend(configBackend)
		prov, err := New(WithProtocolConfig(c))
		require.NoError(t, err)

		pc := prov.ProtocolConfig()
		require.NoError(t, err)
		require.Equal(t, "agent", pc.AgentLabel())

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
		return errors.Errorf("invalid payload data format: %w", err)
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
