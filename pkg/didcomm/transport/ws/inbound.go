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

	"github.com/gorilla/websocket"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

var logger = log.New("aries-framework/ws")

const processFailureErrMsg = "failed to process the message"

// Inbound http(ws) type.
type Inbound struct {
	externalAddr string
	server       *http.Server
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
func (i *Inbound) Start(prov transport.InboundProvider) error {
	handler, err := newInboundHandler(prov)
	if err != nil {
		return fmt.Errorf("websocket server start failed: %w", err)
	}

	i.server.Handler = handler

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

func newInboundHandler(prov transport.InboundProvider) (http.Handler, error) {
	if prov == nil || prov.InboundMessageHandler() == nil {
		logger.Errorf("Error creating a new inbound handler: message handler function is nil")
		return nil, errors.New("creation of inbound handler failed")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		processRequest(w, r, prov)
	}), nil
}

func processRequest(w http.ResponseWriter, r *http.Request, prov transport.InboundProvider) {
	upgrader := websocket.Upgrader{}

	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Errorf("failed to upgrade the connection : %v", err)
		return
	}

	defer func() {
		err := c.Close()
		if err != nil {
			logger.Errorf("failed to close connection: %v", err)
		}
	}()

	for {
		_, message, err := c.ReadMessage()
		if err != nil {
			logger.Errorf("Error reading request message: %v", err)

			break
		}

		unpackMsg, err := prov.Packager().UnpackMessage(message)
		if err != nil {
			logger.Errorf("failed to unpack msg: %v", err)

			err = c.WriteMessage(websocket.TextMessage, []byte(processFailureErrMsg))
			if err != nil {
				logger.Errorf("error writing the message: %v", err)
			}

			continue
		}

		messageHandler := prov.InboundMessageHandler()

		resp := ""

		err = messageHandler(unpackMsg.Message)
		if err != nil {
			logger.Errorf("incoming msg processing failed: %v", err)

			resp = processFailureErrMsg
		}

		err = c.WriteMessage(websocket.TextMessage, []byte(resp))
		if err != nil {
			logger.Errorf("error writing the message: %v", err)
		}
	}
}
