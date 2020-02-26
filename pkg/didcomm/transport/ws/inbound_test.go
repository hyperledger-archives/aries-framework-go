/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ws

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"

	commontransport "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	mockpackager "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/packager"
	"github.com/hyperledger/aries-framework-go/pkg/internal/test/transportutil"
)

func TestInboundTransport(t *testing.T) {
	t.Run("test inbound transport - with host/port", func(t *testing.T) {
		port := ":" + strconv.Itoa(transportutil.GetRandomPort(5))
		externalAddr := "http://example.com" + port
		inbound, err := NewInbound("localhost"+port, externalAddr)
		require.NoError(t, err)
		require.Equal(t, externalAddr, inbound.Endpoint())
	})

	t.Run("test inbound transport - with host/port, no external address", func(t *testing.T) {
		internalAddr := "example.com" + ":" + strconv.Itoa(transportutil.GetRandomPort(5))
		inbound, err := NewInbound(internalAddr, "")
		require.NoError(t, err)
		require.Equal(t, internalAddr, inbound.Endpoint())
	})

	t.Run("test inbound transport - without host/port", func(t *testing.T) {
		inbound, err := NewInbound(":"+strconv.Itoa(transportutil.GetRandomPort(5)), "")
		require.NoError(t, err)
		require.NotEmpty(t, inbound)
		mockPackager := &mockpackager.Packager{UnpackValue: &commontransport.Envelope{Message: []byte("data")}}
		err = inbound.Start(&mockProvider{packagerValue: mockPackager})
		require.NoError(t, err)

		err = inbound.Stop()
		require.NoError(t, err)
	})

	t.Run("test inbound transport - nil context", func(t *testing.T) {
		inbound, err := NewInbound(":"+strconv.Itoa(transportutil.GetRandomPort(5)), "")
		require.NoError(t, err)
		require.NotEmpty(t, inbound)

		err = inbound.Start(nil)
		require.Error(t, err)
	})

	t.Run("test inbound transport - invalid port number", func(t *testing.T) {
		_, err := NewInbound("", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "websocket address is mandatory")
	})
}

func TestInboundDataProcessing(t *testing.T) {
	t.Run("test inbound transport - multiple invocation with same client", func(t *testing.T) {
		port := ":" + strconv.Itoa(transportutil.GetRandomPort(5))

		// initiate inbound with port
		inbound, err := NewInbound(port, "")
		require.NoError(t, err)
		require.NotEmpty(t, inbound)

		// start server
		mockPackager := &mockpackager.Packager{UnpackValue: &commontransport.Envelope{Message: []byte("valid-data")}}
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
		inbound, err := NewInbound(port, "")
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
		inbound, err := NewInbound(port, "")
		require.NoError(t, err)
		require.NotEmpty(t, inbound)

		// start server
		mockPackager := &mockpackager.Packager{UnpackValue: &commontransport.Envelope{Message: []byte("invalid-data")}}
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
		inbound, err := NewInbound(port, "")
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
}
