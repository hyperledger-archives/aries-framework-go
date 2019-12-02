// +build !js,!wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ws

import (
	"net/http"

	"nhooyr.io/websocket"
)

// Accept accepts a WebSocket handshake from a client and upgrades the
// the connection to a WebSocket.
func Accept(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	return websocket.Accept(w, r, nil)
}
