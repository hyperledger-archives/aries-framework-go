/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ws

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/internal/test/transportutil"
	mockpackager "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/packager"
)

const defaultReadLimit = 32768

func TestInboundTransport(t *testing.T) {
	t.Run("test inbound transport - with host/port", func(t *testing.T) {
		port := ":" + strconv.Itoa(transportutil.GetRandomPort(5))
		externalAddr := "http://example.com" + port
		inbound, err := NewInbound("localhost"+port, externalAddr, "", "")
		require.NoError(t, err)
		require.Equal(t, externalAddr, inbound.Endpoint())
	})

	t.Run("test inbound transport - with host/port, no external address", func(t *testing.T) {
		internalAddr := "example.com" + ":" + strconv.Itoa(transportutil.GetRandomPort(5))
		inbound, err := NewInbound(internalAddr, "", "", "")
		require.NoError(t, err)
		require.Equal(t, internalAddr, inbound.Endpoint())
	})

	t.Run("test inbound transport - without host/port", func(t *testing.T) {
		inbound, err := NewInbound(":"+strconv.Itoa(transportutil.GetRandomPort(5)), "", "", "")
		require.NoError(t, err)
		require.NotEmpty(t, inbound)
		mockPackager := &mockpackager.Packager{UnpackValue: &transport.Envelope{Message: []byte("data")}}
		err = inbound.Start(&mockProvider{packagerValue: mockPackager})
		require.NoError(t, err)

		err = inbound.Stop()
		require.NoError(t, err)
	})

	t.Run("test inbound transport - nil context", func(t *testing.T) {
		inbound, err := NewInbound(":"+strconv.Itoa(transportutil.GetRandomPort(5)), "", "", "")
		require.NoError(t, err)
		require.NotEmpty(t, inbound)

		err = inbound.Start(nil)
		require.Error(t, err)
	})

	t.Run("test inbound transport - invalid TLS", func(t *testing.T) {
		svc, err := NewInbound(":0", "", "invalid", "invalid")
		require.NoError(t, err)

		err = svc.listenAndServe()
		require.Error(t, err)
		require.Contains(t, err.Error(), "open invalid: no such file or directory")
	})

	t.Run("test inbound transport - invalid port number", func(t *testing.T) {
		_, err := NewInbound("", "", "", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "websocket address is mandatory")
	})
}

func TestInboundDataProcessing(t *testing.T) {
	t.Run("test inbound transport - multiple invocation with same client", func(t *testing.T) {
		port := ":" + strconv.Itoa(transportutil.GetRandomPort(5))

		// initiate inbound with port
		inbound, err := NewInbound(port, "", "", "")
		require.NoError(t, err)
		require.NotEmpty(t, inbound)

		// start server
		mockPackager := &mockpackager.Packager{UnpackValue: &transport.Envelope{Message: []byte("valid-data")}}
		err = inbound.Start(&mockProvider{packagerValue: mockPackager})
		require.NoError(t, err)

		// create ws client
		client, cleanup := websocketClient(t, port)
		defer cleanup()

		ctx := context.Background()

		for i := 1; i <= 5; i++ {
			err = client.Write(ctx, websocket.MessageText, []byte("random"))
			require.NoError(t, err)
		}
	})

	t.Run("test inbound transport - unpacking error", func(t *testing.T) {
		port := ":" + strconv.Itoa(transportutil.GetRandomPort(5))

		// initiate inbound with port
		inbound, err := NewInbound(port, "", "", "")
		require.NoError(t, err)
		require.NotEmpty(t, inbound)

		// start server
		mockPackager := &mockpackager.Packager{UnpackErr: errors.New("error unpacking")}
		err = inbound.Start(&mockProvider{packagerValue: mockPackager})
		require.NoError(t, err)

		// create ws client
		client, cleanup := websocketClient(t, port)
		defer cleanup()

		ctx := context.Background()

		err = client.Write(ctx, websocket.MessageText, []byte(""))
		require.NoError(t, err)
	})

	t.Run("test inbound transport - message handler error", func(t *testing.T) {
		port := ":" + strconv.Itoa(transportutil.GetRandomPort(5))

		// initiate inbound with port
		inbound, err := NewInbound(port, "", "", "")
		require.NoError(t, err)
		require.NotEmpty(t, inbound)

		// start server
		mockPackager := &mockpackager.Packager{UnpackValue: &transport.Envelope{Message: []byte("invalid-data")}}
		err = inbound.Start(&mockProvider{packagerValue: mockPackager})
		require.NoError(t, err)

		// create ws client
		client, cleanup := websocketClient(t, port)
		defer cleanup()

		ctx := context.Background()

		err = client.Write(ctx, websocket.MessageText, []byte(""))
		require.NoError(t, err)
	})

	t.Run("test inbound transport - client close error", func(t *testing.T) {
		port := ":" + strconv.Itoa(transportutil.GetRandomPort(5))

		// initiate inbound with port
		inbound, err := NewInbound(port, "", "", "")
		require.NoError(t, err)
		require.NotEmpty(t, inbound)

		// start server
		mockPackager := &mockpackager.Packager{}
		err = inbound.Start(&mockProvider{packagerValue: mockPackager})
		require.NoError(t, err)

		// create ws client
		client, _ := websocketClient(t, port)

		err = client.Close(websocket.StatusInternalError, "abnormal closure")
		require.NoError(t, err)
	})

	t.Run("test inbound transport - custom read limit for a single message", func(t *testing.T) {
		port := ":" + strconv.Itoa(transportutil.GetRandomPort(5))

		// initiate inbound with a port and a custom read limit
		inbound, err := NewInbound(port, "", "", "", WithInboundReadLimit(defaultReadLimit+1))
		require.NoError(t, err)
		require.NotEmpty(t, inbound)

		trans := &decorator.Transport{
			ReturnRoute: &decorator.ReturnRoute{
				Value: decorator.TransportReturnRouteNone,
			},
		}

		unpackMsg, err := json.Marshal(trans)
		require.NoError(t, err)

		fromKey, err := json.Marshal(&cryptoapi.PublicKey{KID: "keyID"})
		require.NoError(t, err)

		mockPackager := &mockpackager.Packager{
			UnpackValue: &transport.Envelope{
				Message: unpackMsg,
				FromKey: fromKey,
			},
		}

		done := make(chan struct{})

		// start server
		err = inbound.Start(&mockTransportProvider{
			packagerValue: mockPackager,
			executeInbound: func(envelope *transport.Envelope) error {
				done <- struct{}{}
				return nil
			},
		})
		require.NoError(t, err)

		// create ws client
		client, cleanup := websocketClient(t, port)
		defer cleanup()

		msg := make([]byte, defaultReadLimit+1)

		err = client.Write(context.Background(), websocket.MessageText, msg)
		require.NoError(t, err)

		select {
		case <-done:
		case <-time.After(3 * time.Second):
			require.Fail(t, "inbound message handler was not called within given timeout")
		}
	})
}
