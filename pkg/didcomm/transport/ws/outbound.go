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
	pool      *connPool
	prov      transport.Provider
	readLimit int64
}

// OutboundClientOpt configures outbound client.
type OutboundClientOpt func(c *OutboundClient)

// WithOutboundReadLimit sets the custom max number of bytes to read for a single message.
func WithOutboundReadLimit(n int64) OutboundClientOpt {
	return func(c *OutboundClient) {
		c.readLimit = n
	}
}

// NewOutbound creates a client for Outbound WS transport.
func NewOutbound(opts ...OutboundClientOpt) *OutboundClient {
	c := &OutboundClient{}

	for _, opt := range opts {
		opt(c)
	}

	return c
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
		logger.Errorf("didcomm failed : transport=ws serviceEndpoint=%s errMsg=%s",
			destination.ServiceEndpoint, err.Error())

		return "", fmt.Errorf("websocket write message : %w", err)
	}

	return "", nil
}

// Accept checks for the url scheme.
func (cs *OutboundClient) Accept(url string) bool {
	return strings.HasPrefix(url, webSocketScheme)
}

// AcceptRecipient checks if there is a connection for the list of recipient keys.
func (cs *OutboundClient) AcceptRecipient(keys []string) bool {
	return acceptRecipient(cs.pool, keys)
}

//nolint:gocyclo,funlen
func (cs *OutboundClient) getConnection(destination *service.Destination) (*websocket.Conn, func(), error) {
	var conn *websocket.Conn

	// get the connection for the routing or recipient keys
	keys := destination.RecipientKeys
	if routingKeys, err := destination.ServiceEndpoint.RoutingKeys(); err == nil && len(routingKeys) != 0 {
		keys = routingKeys
	} else if len(destination.RoutingKeys) != 0 {
		keys = destination.RoutingKeys
	}

	for _, v := range keys {
		if c := cs.pool.fetch(v); c != nil {
			conn = c

			break
		}
	}

	cleanup := func() {}

	if conn != nil {
		return conn, cleanup, nil
	}

	var (
		err error
		uri string
	)

	uri, err = destination.ServiceEndpoint.URI()
	if err != nil {
		return nil, cleanup, fmt.Errorf("unable to send ws outbound request: %w", err)
	}

	conn, _, err = websocket.Dial(context.Background(), uri, nil)
	if err != nil {
		return nil, cleanup, fmt.Errorf("websocket client : %w", err)
	}

	if cs.readLimit > 0 {
		conn.SetReadLimit(cs.readLimit)
	}

	// keep the connection open to listen to the response in case of return route option set
	if destination.TransportReturnRoute == decorator.TransportReturnRouteAll {
		for _, v := range destination.RecipientKeys {
			cs.pool.add(v, conn)
		}

		go cs.pool.listener(conn, true)

		return conn, cleanup, nil
	}

	cleanup = func() {
		err = conn.Close(websocket.StatusNormalClosure, "closing the connection")
		if err != nil && websocket.CloseStatus(err) != websocket.StatusNormalClosure {
			logger.Errorf("failed to close connection: %v", err)
		}
	}

	return conn, cleanup, nil
}
