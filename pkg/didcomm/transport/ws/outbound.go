/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ws

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gorilla/websocket"
)

const webSocketScheme = "ws"

// OutboundClient websocket outbound.
type OutboundClient struct {
}

// NewOutbound creates a client for Outbound WS transport.
func NewOutbound() *OutboundClient {
	return &OutboundClient{}
}

// Send sends a2a data via WS.
func (cs *OutboundClient) Send(data []byte, url string) (string, error) {
	if url == "" {
		return "", errors.New("url is mandatory")
	}

	client, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		return "", fmt.Errorf("websocket client : %w", err)
	}

	defer func() {
		err = client.Close()
		if err != nil {
			logger.Errorf("failed to close connection: %v", err)
		}
	}()

	err = client.WriteMessage(websocket.TextMessage, data)
	if err != nil {
		return "", fmt.Errorf("websocket write message : %w", err)
	}

	messageType, message, err := client.ReadMessage()
	if err != nil {
		return "", fmt.Errorf("websocket read message : %w", err)
	}

	if messageType != websocket.TextMessage {
		return "", errors.New("message type is not text message")
	}

	return string(message), nil
}

// Accept checks for the url scheme.
func (cs *OutboundClient) Accept(url string) bool {
	return strings.HasPrefix(url, webSocketScheme)
}
