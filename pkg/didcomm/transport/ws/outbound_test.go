/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ws

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/internal/test/transportutil"

	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"
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

		_, err := outbound.Send([]byte(""), "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "url is mandatory")
	})

	t.Run("test outbound transport - invalid url", func(t *testing.T) {
		outbound := NewOutbound()
		require.NotNil(t, outbound)

		_, err := outbound.Send([]byte(""), "ws://invalid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "websocket client")
	})

	t.Run("test outbound transport - success", func(t *testing.T) {
		outbound := NewOutbound()
		require.NotNil(t, outbound)
		addr := startWebSocketServer(t, echo)

		data := "hello"
		resp, err := outbound.Send([]byte(data), "ws://"+addr)
		require.NoError(t, err)
		require.Equal(t, data, resp)
	})

	t.Run("test outbound transport - not a websocket server", func(t *testing.T) {
		outbound := NewOutbound()
		require.NotNil(t, outbound)
		addr := startWebSocketServer(t, func(_ *testing.T, w http.ResponseWriter, r *http.Request) {
			logger.Infof("inside http path")
		})

		_, err := outbound.Send([]byte("ws-request"), "ws://"+addr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "websocket client")
	})

	t.Run("test outbound transport - not a websocket server", func(t *testing.T) {
		outbound := NewOutbound()
		require.NotNil(t, outbound)
		addr := startWebSocketServer(t, func(_ *testing.T, w http.ResponseWriter, r *http.Request) {
			c, err := websocket.Accept(w, r, nil)
			require.NoError(t, err)

			defer func() {
				require.Contains(t, c.Close(websocket.StatusNormalClosure, "closing the connection").Error(),
					"status = StatusNormalClosure")
			}()

			ctx := context.Background()

			for {
				_, message, err := c.Read(ctx)
				if err != nil {
					break
				}

				logger.Infof("r: %s", message)

				err = c.Write(ctx, websocket.MessageBinary, message)
				require.NoError(t, err)
			}
		})

		_, err := outbound.Send([]byte("ws-request"), "ws://"+addr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "message type is not text message")
	})

	t.Run("test outbound transport - server closes connection", func(t *testing.T) {
		outbound := NewOutbound()
		require.NotNil(t, outbound)
		addr := startWebSocketServer(t, func(_ *testing.T, w http.ResponseWriter, r *http.Request) {
			c, err := websocket.Accept(w, r, nil)
			require.NoError(t, err)

			require.NoError(t, c.Close(websocket.StatusAbnormalClosure, "error"))
		})

		_, err := outbound.Send([]byte("ws-request"), "ws://"+addr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "websocket read message")
	})

	t.Run("test outbound transport - not a websocket server", func(t *testing.T) {
		outbound := NewOutbound()
		require.NotNil(t, outbound)
		addr := startWebSocketServer(t, func(_ *testing.T, w http.ResponseWriter, r *http.Request) {
			c, err := websocket.Accept(w, r, nil)
			require.NoError(t, err)

			_, _, err = c.Read(context.Background())
			require.NoError(t, err)

			require.NoError(t, c.Close(websocket.StatusNormalClosure, "closing the connection"))
		})

		_, err := outbound.Send([]byte("ws-request"), "ws://"+addr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "websocket read message")
	})
}

func startWebSocketServer(t *testing.T, handlerFunc func(*testing.T, http.ResponseWriter, *http.Request)) string {
	addr := "localhost:" + strconv.Itoa(transportutil.GetRandomPort(5))

	server := &http.Server{Addr: addr}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerFunc(t, w, r)
	})

	go func() {
		require.NoError(t, server.ListenAndServe())
	}()

	require.NoError(t, transportutil.VerifyListener(addr, time.Second))

	return addr
}

func echo(t *testing.T, w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, nil)
	require.NoError(t, err)

	defer func() {
		require.Contains(t, c.Close(websocket.StatusNormalClosure, "closing the connection").Error(),
			"status = StatusNormalClosure")
	}()

	ctx := context.Background()

	for {
		mt, message, err := c.Read(ctx)
		if err != nil {
			break
		}

		logger.Infof("r: %s", message)

		err = c.Write(ctx, mt, message)
		require.NoError(t, err)
	}
}
