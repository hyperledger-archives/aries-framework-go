// +build !js,!wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ws

import (
	"context"
	"net/http"
	"time"

	"nhooyr.io/websocket"
)

// Accept accepts a WebSocket handshake from a client and upgrades the connection to a WebSocket.
func Accept(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	// TODO Allow user to enable InsecureSkipVerify https://github.com/hyperledger/aries-framework-go/issues/928
	return websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
		CompressionMode:    websocket.CompressionDisabled,
	})
}

func acceptRecipient(pool *connPool, keys []string) bool {
	for _, v := range keys {
		// check if the connection exists for the key
		if c := pool.fetch(v); c != nil {
			// verify the connection is alive
			if err := c.Ping(context.Background()); err != nil {
				// remove from the pool
				pool.remove(v)

				logger.Infof("failed to ping to the connection for key=%s err=%v. Connection removed from pool.", v, err)

				return false
			}

			return true
		}
	}

	return false
}

// keepConnAlive sends the pings the server based on time frequency. The web server, load balancer, network routers
// between the client and server closes the TCP keepalives connection. This function calls websocket ping request
// directly to the server and keeps the connection active.
func keepConnAlive(conn *websocket.Conn, outbound bool, frequency time.Duration) {
	if outbound {
		ticker := time.NewTicker(frequency)
		done := make(chan struct{})

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if err := conn.Ping(context.Background()); err != nil {
					logger.Errorf("websocket ping error : %v", err)

					ticker.Stop()
					done <- struct{}{}
				}
			}
		}
	}
}
