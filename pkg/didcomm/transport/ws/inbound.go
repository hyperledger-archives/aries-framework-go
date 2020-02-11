/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ws

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"nhooyr.io/websocket"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

var logger = log.New("aries-framework/ws")

// Inbound http(ws) type.
type Inbound struct {
	externalAddr string
	server       *http.Server
	pool         *connPool
}

// NewInbound creates a new WebSocket inbound transport instance.
func NewInbound(internalAddr, externalAddr string) (*Inbound, error) {
	if internalAddr == "" {
		return nil, errors.New("websocket address is mandatory")
	}

	if externalAddr == "" {
		return &Inbound{externalAddr: internalAddr, server: &http.Server{Addr: internalAddr}}, nil
	}

	return &Inbound{externalAddr: externalAddr, server: &http.Server{Addr: internalAddr}}, nil
}

// Start the http(ws) server.
func (i *Inbound) Start(prov transport.Provider) error {
	if prov == nil || prov.InboundMessageHandler() == nil {
		return errors.New("creation of inbound handler failed")
	}

	i.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i.processRequest(w, r)
	})

	i.pool = getConnPool(prov)

	go func() {
		if err := i.server.ListenAndServe(); err != http.ErrServerClosed {
			logger.Fatalf("websocket server start with address [%s] failed, cause:  %s", i.server.Addr, err)
		}
	}()

	return nil
}

// Stop the http(ws) server.
func (i *Inbound) Stop() error {
	if err := i.server.Shutdown(context.Background()); err != nil {
		return fmt.Errorf("websocket server shutdown failed: %w", err)
	}

	return nil
}

// Endpoint provides the http(ws) connection details.
func (i *Inbound) Endpoint() string {
	return i.externalAddr
}

func (i *Inbound) processRequest(w http.ResponseWriter, r *http.Request) {
	c, err := upgradeConnection(w, r)
	if err != nil {
		logger.Errorf("failed to upgrade the connection : %v", err)
		return
	}

	i.pool.listener(c, false)
}

func upgradeConnection(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	c, err := Accept(w, r)
	if err != nil {
		logger.Errorf("failed to upgrade the connection : %v", err)
		return nil, err
	}

	return c, nil
}
