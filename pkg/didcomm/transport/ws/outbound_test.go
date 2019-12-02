/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ws

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	commontransport "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	mockpackager "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/packager"
)

func TestClient(t *testing.T) {
	t.Run("test outbound transport - accept", func(t *testing.T) {
		outbound := NewOutbound()
		require.NotNil(t, outbound)

		require.True(t, outbound.Accept(webSocketScheme))
		require.False(t, outbound.Accept("http"))
	})

	t.Run("test outbound transport - missing url", func(t *testing.T) {
		outbound := NewOutbound()
		require.NotNil(t, outbound)

		_, err := outbound.Send([]byte(""), prepareDestination(""))
		require.Error(t, err)
		require.Contains(t, err.Error(), "url is mandatory")
	})

	t.Run("test outbound transport - invalid url", func(t *testing.T) {
		outbound := NewOutbound()
		require.NotNil(t, outbound)

		_, err := outbound.Send([]byte(""), prepareDestination("ws://invalid"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "websocket client")
	})

	t.Run("test outbound transport - success", func(t *testing.T) {
		outbound := NewOutbound()
		require.NotNil(t, outbound)
		addr := startWebSocketServer(t, echo)

		data := "hello"
		resp, err := outbound.Send([]byte(data), prepareDestination("ws://"+addr))
		require.NoError(t, err)
		require.Equal(t, "", resp)
	})

	t.Run("test outbound transport - not a websocket server", func(t *testing.T) {
		outbound := NewOutbound()
		require.NotNil(t, outbound)
		addr := startWebSocketServer(t, func(_ *testing.T, w http.ResponseWriter, r *http.Request) {
			logger.Infof("inside http path")
		})

		_, err := outbound.Send([]byte("ws-request"), prepareDestination("ws://"+addr))
		require.Error(t, err)
		require.Contains(t, err.Error(), "websocket client")
	})

	t.Run("test outbound transport pool success - no existing connections", func(t *testing.T) {
		outbound := NewOutbound()
		require.NotNil(t, outbound)

		require.NoError(t, outbound.Start(&mockProvider{}))

		addr := startWebSocketServer(t, echo)

		data := "hello"
		resp, err := outbound.Send([]byte(data), prepareDestination("ws://"+addr))
		require.NoError(t, err)
		require.Equal(t, "", resp)
	})

	t.Run("test outbound transport pool success - transport decorator", func(t *testing.T) {
		outbound := NewOutbound()
		require.NotNil(t, outbound)

		require.NoError(t, outbound.Start(&mockProvider{
			&mockpackager.Packager{UnpackValue: &commontransport.Envelope{Message: []byte("data")}}},
		))

		addr := startWebSocketServer(t, echo)

		resp, err := outbound.Send(createTransportDecRequest(t, decorator.TransportReturnRouteAll),
			prepareDestinationWithTransport("ws://"+addr, decorator.TransportReturnRouteAll, nil))
		require.NoError(t, err)
		require.Equal(t, "", resp)
	})
}
