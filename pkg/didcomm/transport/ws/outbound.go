/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ws

import (
	"context"
	"fmt"
	"strings"

	"nhooyr.io/websocket"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

const webSocketScheme = "ws"

// OutboundClient websocket outbound.
type OutboundClient struct {
	pool *connPool
	prov transport.Provider
}

// NewOutbound creates a client for Outbound WS transport.
func NewOutbound() *OutboundClient {
	return &OutboundClient{}
}

// Start starts the outbound transport.
func (cs *OutboundClient) Start(prov transport.Provider) error {
	cs.pool = getConnPool(prov)
	cs.prov = prov

	return nil
}

// Send sends a2a data via WS.
func (cs *OutboundClient) Send(data []byte, destination *service.Destination) (string, error) {
	conn, cleanup, err := cs.getConnection(destination)
	defer cleanup()

	if err != nil {
		return "", fmt.Errorf("get websocket connection : %w", err)
	}

	err = conn.Write(context.Background(), websocket.MessageText, data)
	if err != nil {
		return "", fmt.Errorf("websocket write message : %w", err)
	}

	return "", nil
}

// Accept checks for the url scheme.
func (cs *OutboundClient) Accept(url string) bool {
	return strings.HasPrefix(url, webSocketScheme)
}

// AcceptRecipient checks if there is a connection for the list of recipient keys
func (cs *OutboundClient) AcceptRecipient(keys []string) bool {
	return acceptRecipient(cs.pool, keys)
}

func (cs *OutboundClient) getConnection(destination *service.Destination) (*websocket.Conn, func(), error) {
	var conn *websocket.Conn

	// get the connection for the routing or recipient keys
	keys := destination.RecipientKeys
	if len(destination.RoutingKeys) != 0 {
		keys = destination.RoutingKeys
	}

	for _, v := range keys {
		if c := cs.pool.fetch(v); c != nil {
			conn = c

			break
		}
	}

	cleanup := func() {}

	if conn == nil {
		var err error

		conn, _, err = websocket.Dial(context.Background(), destination.ServiceEndpoint, nil)
		if err != nil {
			return nil, cleanup, fmt.Errorf("websocket client : %w", err)
		}

		// keep the connection open to listen to the response in case of return route option set
		if destination.TransportReturnRoute == decorator.TransportReturnRouteAll {
			for _, v := range destination.RecipientKeys {
				cs.pool.add(v, conn)
			}

			go cs.pool.listener(conn, true)
		} else {
			cleanup = func() {
				err = conn.Close(websocket.StatusNormalClosure, "closing the connection")
				if err != nil && websocket.CloseStatus(err) != websocket.StatusNormalClosure {
					logger.Errorf("failed to close connection: %v", err)
				}
			}
		}
	}

	return conn, cleanup, nil
}
