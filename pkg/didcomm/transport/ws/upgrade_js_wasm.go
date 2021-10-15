/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ws

import (
	"errors"
	"net/http"
	"time"

	"nhooyr.io/websocket"
)

// Accept accepts a WebSocket handshake from a client and upgrades connection to a WebSocket.
func Accept(_ http.ResponseWriter, _ *http.Request) (*websocket.Conn, error) {
	return nil, errors.New("invalid operation with JS/WASM target")
}

func acceptRecipient(pool *connPool, keys []string) bool {
	for _, v := range keys {
		// check if the connection exists for the key
		if c := pool.fetch(v); c != nil {
			// TODO make sure connection is alive (conn.Ping() doesn't work with JS/WASM build)
			return true
		}
	}

	return false
}

func keepConnAlive(conn *websocket.Conn, outbound bool, frequency time.Duration) {
	// TODO make sure connection is alive (conn.Ping() doesn't work with JS/WASM build)
}
