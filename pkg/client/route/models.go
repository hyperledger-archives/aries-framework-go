/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/route"
)

const (
	// RequestMsgType defines the route coordination request message type.
	RequestMsgType = route.RequestMsgType
)

// Request is the route-request message of this protocol.
type Request = route.Request

// NewRequest creates a new request.
func NewRequest() *Request {
	return &Request{
		ID:   uuid.New().String(),
		Type: RequestMsgType,
	}
}
