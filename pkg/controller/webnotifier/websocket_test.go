/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webnotifier

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"

	"github.com/hyperledger/aries-framework-go/pkg/internal/test/transportutil"
)

func TestConnectionsWS(t *testing.T) {
	const path = "/ws"

	n := NewWSNotifier(path)
	clientHost := randomURL()

	startWSListener(t, n, clientHost)
	require.Equal(t, 0, len(n.conns))

	t.Run("normal client lifecycle", func(t *testing.T) {
		conn1, _, err := websocket.Dial(context.Background(), "ws://"+clientHost+path, nil) //nolint:bodyclose
		require.NoError(t, err)
		validateConnCount(t, n, 1)

		err = conn1.Close(websocket.StatusNormalClosure, "")
		require.NoError(t, err)
		validateConnCount(t, n, 0)
	})

	t.Run("abnormal client closure", func(t *testing.T) {
		conn1, _, err := websocket.Dial(context.Background(), "ws://"+clientHost+path, nil) //nolint:bodyclose
		require.NoError(t, err)
		validateConnCount(t, n, 1)

		err = conn1.Close(websocket.StatusInternalError, "broken")
		require.NoError(t, err)
		validateConnCount(t, n, 0)
	})

	t.Run("multiple clients", func(t *testing.T) {
		conn1, _, err := websocket.Dial(context.Background(), "ws://"+clientHost+path, nil) //nolint:bodyclose
		require.NoError(t, err)
		validateConnCount(t, n, 1)

		conn2, _, err := websocket.Dial(context.Background(), "ws://"+clientHost+path, nil) //nolint:bodyclose
		require.NoError(t, err)
		validateConnCount(t, n, 2)

		err = conn1.Close(websocket.StatusNormalClosure, "done")
		require.NoError(t, err)
		validateConnCount(t, n, 1)

		err = conn2.Close(websocket.StatusNormalClosure, "")
		require.NoError(t, err)
		validateConnCount(t, n, 0)
	})
}

func validateConnCount(t *testing.T, n *WSNotifier, expectedCount int) {
	t.Helper()

	const (
		attemptWait = 50 * time.Millisecond
		maxAttempts = 20
	)

	for i := 0; i < maxAttempts; i++ {
		n.connsLock.RLock()
		connCount := len(n.conns)
		n.connsLock.RUnlock()

		if connCount == expectedCount {
			return
		}

		time.Sleep(attemptWait)
	}

	t.Fatal("invalid connection count")
}

func TestNotifyWS(t *testing.T) {
	const (
		path     = "/ws"
		timeout  = 2 * time.Second
		expTopic = "example"
	)

	payloads := []string{
		`{"msg":"payload1"}`, `{"msg":"payload2"}`, `{"msg":"payload3"}`,
		`{"msg":"payload4"}`, `{"msg":"payload5"}`,
	}

	n := NewWSNotifier(path)
	clientHost := randomURL()

	startWSListener(t, n, clientHost)

	dial := func(url string) *websocket.Conn {
		conn, _, err := websocket.Dial(context.Background(), url, nil) //nolint:bodyclose
		require.NoError(t, err)

		return conn
	}

	t.Run("sequential notifications", func(t *testing.T) {
		conn := dial("ws://" + clientHost + path)
		validateConnCount(t, n, 1)

		for _, expPayload := range payloads {
			err := n.Notify(expTopic, []byte(expPayload))
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			msgType, payload, err := conn.Read(ctx)
			cancel()
			require.NoError(t, err)

			var topic struct {
				ID      string          `json:"id"`
				Topic   string          `json:"topic"`
				Message json.RawMessage `json:"message"`
			}
			err = json.Unmarshal(payload, &topic)
			require.NoError(t, err)

			b, err := topic.Message.MarshalJSON()
			require.NoError(t, err)

			require.Equal(t, websocket.MessageText, msgType)
			require.Equal(t, []byte(expPayload), b)
		}

		err := conn.Close(websocket.StatusNormalClosure, "")
		require.NoError(t, err)
	})

	t.Run("burst notifications", func(t *testing.T) {
		conn := dial("ws://" + clientHost + path)
		validateConnCount(t, n, 1)

		for _, expPayload := range payloads {
			err := n.Notify(expTopic, []byte(expPayload))
			require.NoError(t, err)
		}

		for _, expPayload := range payloads {
			var (
				payload []byte
				msgType websocket.MessageType
			)

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			msgType, payload, err := conn.Read(ctx)
			cancel()
			require.NoError(t, err)

			var topic struct {
				ID      string          `json:"id"`
				Topic   string          `json:"topic"`
				Message json.RawMessage `json:"message"`
			}
			err = json.Unmarshal(payload, &topic)
			require.NoError(t, err)

			b, err := topic.Message.MarshalJSON()
			require.NoError(t, err)

			require.Equal(t, websocket.MessageText, msgType)
			require.Equal(t, []byte(expPayload), b)
		}

		err := conn.Close(websocket.StatusNormalClosure, "")
		require.NoError(t, err)
	})
}

func startWSListener(t *testing.T, n *WSNotifier, clientHost string) {
	t.Helper()

	const timeout = 2 * time.Second

	handlers := n.GetRESTHandlers()
	handler := handlers[0]

	router := mux.NewRouter()
	router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())

	srv := &http.Server{Addr: clientHost, Handler: router}

	go func() {
		err := srv.ListenAndServe()
		require.NoError(t, err)
	}()

	if err := transportutil.VerifyListener(clientHost, timeout); err != nil {
		t.Fatal(err)
	}
}
