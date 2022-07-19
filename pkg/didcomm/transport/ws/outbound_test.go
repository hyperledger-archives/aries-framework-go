/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ws

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	mockpackager "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/packager"
)

func TestClient(t *testing.T) {
	t.Run("test outbound transport - accept", func(t *testing.T) {
		outbound := NewOutbound()
		require.NotNil(t, outbound)

		require.True(t, outbound.Accept(webSocketScheme))
		require.False(t, outbound.Accept("http"))
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

	t.Run("test outbound transport pool - accept recipients", func(t *testing.T) {
		verKey := "XYZ"
		recKey := []string{verKey}

		outbound := NewOutbound()
		require.NotNil(t, outbound)

		require.NoError(t, outbound.Start(&mockProvider{
			&mockpackager.Packager{UnpackValue: &transport.Envelope{Message: []byte("data")}},
		},
		))

		addr := startWebSocketServer(t, echo)

		resp, err := outbound.Send(createTransportDecRequest(t, decorator.TransportReturnRouteAll),
			prepareDestinationWithTransport("ws://"+addr, decorator.TransportReturnRouteAll, recKey, nil))
		require.NoError(t, err)
		require.Equal(t, "", resp)

		// verify connection exists for the verKey
		require.True(t, outbound.AcceptRecipient(recKey))

		// close the connection and verify
		conn := outbound.pool.fetch(verKey)
		require.NoError(t, conn.Close(websocket.StatusNormalClosure, "close conn"))
		require.False(t, outbound.AcceptRecipient(recKey))

		// connection was remove in prev step
		require.False(t, outbound.AcceptRecipient(recKey))
	})

	t.Run("test outbound transport pool - accept routing keys", func(t *testing.T) {
		verKey := "XYZ"
		routeKey := "ABC"
		recKey := []string{verKey}
		routingKeys := []string{routeKey}

		outbound := NewOutbound()
		require.NotNil(t, outbound)

		require.NoError(t, outbound.Start(&mockProvider{
			&mockpackager.Packager{UnpackValue: &transport.Envelope{Message: []byte("data")}},
		},
		))

		addr := startWebSocketServer(t, echo)

		des := prepareDestinationWithTransport("ws://"+addr, decorator.TransportReturnRouteAll, recKey, routingKeys)

		data := "didcomm-message"
		resp, err := outbound.Send([]byte(data), des)
		require.NoError(t, err)
		require.Equal(t, "", resp)
	})

	t.Run("test outbound transport pool success - transport decorator", func(t *testing.T) {
		outbound := NewOutbound()
		require.NotNil(t, outbound)

		require.NoError(t, outbound.Start(&mockProvider{
			&mockpackager.Packager{UnpackValue: &transport.Envelope{Message: []byte("data")}},
		},
		))

		addr := startWebSocketServer(t, echo)

		resp, err := outbound.Send(createTransportDecRequest(t, decorator.TransportReturnRouteAll),
			prepareDestinationWithTransport("ws://"+addr, decorator.TransportReturnRouteAll, nil, nil))
		require.NoError(t, err)
		require.Equal(t, "", resp)
	})

	t.Run("test outbound transport pool - transport decorator value none", func(t *testing.T) {
		outbound := NewOutbound()
		require.NotNil(t, outbound)

		require.NoError(t, outbound.Start(&mockProvider{
			&mockpackager.Packager{UnpackValue: &transport.Envelope{Message: []byte("data")}},
		},
		))

		addr := startWebSocketServer(t, echo)

		resp, err := outbound.Send(createTransportDecRequest(t, decorator.TransportReturnRouteNone),
			prepareDestinationWithTransport("ws://"+addr, decorator.TransportReturnRouteNone, nil, nil))
		require.NoError(t, err)
		require.Equal(t, "", resp)
	})

	t.Run("test outbound transport - custom read limit for a single message", func(t *testing.T) {
		outboundClient := NewOutbound(WithOutboundReadLimit(defaultReadLimit + 1))
		require.NotNil(t, outboundClient)

		done := make(chan struct{})

		unpackMsg, err := json.Marshal(&decorator.Transport{
			ReturnRoute: &decorator.ReturnRoute{
				Value: decorator.TransportReturnRouteAll,
			},
		})
		require.NoError(t, err)

		fromKey, err := json.Marshal(&cryptoapi.PublicKey{KID: "keyID"})
		require.NoError(t, err)

		transportProvider := &mockTransportProvider{
			frameworkID: uuid.New().String(),
			packagerValue: &mockpackager.Packager{
				UnpackValue: &transport.Envelope{Message: unpackMsg, FromKey: fromKey},
			},
			executeInbound: func(envelope *transport.Envelope) error {
				done <- struct{}{}
				return nil
			},
		}

		addr := startWebSocketServer(t, func(t *testing.T, w http.ResponseWriter, r *http.Request) {
			c, errAcc := Accept(w, r)
			require.NoError(t, errAcc)

			defer func() {
				require.NoError(t, c.Close(websocket.StatusNormalClosure, "closing the connection"))
			}()

			bigMsg := make([]byte, defaultReadLimit+1)

			errWrite := c.Write(context.Background(), websocket.MessageText, bigMsg)
			require.NoError(t, errWrite)
		})

		err = outboundClient.Start(transportProvider)
		require.NoError(t, err)

		resp, err := outboundClient.Send([]byte("data"),
			prepareDestinationWithTransport("ws://"+addr, decorator.TransportReturnRouteAll, nil, nil))
		require.NoError(t, err)
		require.Equal(t, "", resp)

		select {
		case <-done:
		case <-time.After(3 * time.Second):
			require.Fail(t, "inbound message handler was not called within given timeout")
		}
	})
}
