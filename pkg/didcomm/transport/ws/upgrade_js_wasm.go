/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ws

import (
	"errors"
	"net/http"

	"nhooyr.io/websocket"
)

// Accept accepts a WebSocket handshake from a client and upgrades the
// the connection to a WebSocket.
func Accept(_ http.ResponseWriter, _ *http.Request) (*websocket.Conn, error) {
	return nil, errors.New("invalid operation with JS/WASM target")
}
