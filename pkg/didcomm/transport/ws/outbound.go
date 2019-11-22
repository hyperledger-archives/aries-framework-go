/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ws

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"nhooyr.io/websocket"
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

	client, _, err := websocket.Dial(context.Background(), url, nil)
	if err != nil {
		return "", fmt.Errorf("websocket client : %w", err)
	}

	defer func() {
		err = client.Close(websocket.StatusNormalClosure, "closing the connection")
		if err != nil && websocket.CloseStatus(err) != websocket.StatusNormalClosure {
			logger.Errorf("failed to close connection: %v", err)
		}
	}()

	ctx := context.Background()

	err = client.Write(ctx, websocket.MessageText, data)
	if err != nil {
		return "", fmt.Errorf("websocket write message : %w", err)
	}

	messageType, message, err := client.Read(ctx)
	if err != nil {
		return "", fmt.Errorf("websocket read message : %w", err)
	}

	if messageType != websocket.MessageText {
		return "", errors.New("message type is not text message")
	}

	return string(message), nil
}

// Accept checks for the url scheme.
func (cs *OutboundClient) Accept(url string) bool {
	return strings.HasPrefix(url, webSocketScheme)
}
