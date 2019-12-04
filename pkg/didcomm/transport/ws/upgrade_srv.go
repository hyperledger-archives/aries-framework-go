// +build !js,!wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ws

import (
	"context"
	"net/http"

	"nhooyr.io/websocket"
)

// Accept accepts a WebSocket handshake from a client and upgrades the
// the connection to a WebSocket.
func Accept(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	return websocket.Accept(w, r, nil)
}

func acceptRecipient(pool *connPool, keys []string) bool {
	for _, v := range keys {
		// check if the connection exists for the key
		if c := pool.fetch(v); c != nil {
			// verify the connection is alive
			if err := c.Ping(context.Background()); err != nil {
				// remove from the pool
				pool.remove(v)

				logger.Infof("failed to ping to the connection for key=%s err=%v", err)

				return false
			}

			return true
		}
	}

	return false
}
