/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"github.com/go-openapi/runtime/middleware/denco"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

//Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() denco.HandlerFunc
}

// ProtocolSvc interface for protocol service
type ProtocolSvc interface {
	GetRESTHandlers() []Handler
}

// Provider interface for protocol ctx
type Provider interface {
	OutboundTransport() transport.OutboundTransport
}

// ProtocolSvcCreator method to create new protocol service
type ProtocolSvcCreator func(prv Provider) (ProtocolSvc, error)
