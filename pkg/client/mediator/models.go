/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import (
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
)

const (
	// ProtocolName is the framework's friendly name for the route-coordination protocol.
	ProtocolName = mediator.Coordination
	// RequestMsgType defines the route coordination request message type.
	RequestMsgType = mediator.RequestMsgType
)

// Request is the route-request message of this protocol.
type Request = mediator.Request

// ConnectionOption option for Client.GetConnections.
type ConnectionOption = mediator.ConnectionOption

// NewRequest creates a new request.
func NewRequest() *Request {
	return &Request{
		ID:   uuid.New().String(),
		Type: RequestMsgType,
	}
}
