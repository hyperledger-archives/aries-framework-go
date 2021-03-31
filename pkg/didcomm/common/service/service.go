/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

// InboundHandler is handler for inbound messages.
type InboundHandler interface {
	// HandleInbound handles inbound messages.
	HandleInbound(msg DIDCommMsg, ctx DIDCommContext) (string, error)
}

// OutboundHandler is handler for outbound messages.
type OutboundHandler interface {
	// HandleOutbound handles outbound messages.
	HandleOutbound(msg DIDCommMsg, myDID, theirDID string) (string, error)
}

// Handler provides protocol service handle api.
type Handler interface {
	InboundHandler
	OutboundHandler
}

// DIDComm defines service APIs.
type DIDComm interface {
	// service handler
	Handler
	// event service
	Event
}
