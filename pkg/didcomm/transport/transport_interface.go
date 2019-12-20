/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package transport

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
)

// OutboundTransport interface definition for transport layer
// This is the client side of the agent
type OutboundTransport interface {
	// starts the outbound transport
	Start(prov Provider) error

	// Send send a2a exchange data
	Send(data []byte, destination *service.Destination) (string, error)

	// AcceptRecipient checks if there is a connection for the list of recipient keys. The framework executes this
	// function before Accept() in outbound message dispatcher.
	AcceptRecipient([]string) bool

	// Accept url
	Accept(string) bool
}

// InboundMessageHandler handles the inbound requests. The transport will unpack the payload prior to the
// message handle invocation.
type InboundMessageHandler func(message []byte, myDID, theirDID string) error

// Provider contains dependencies for starting the inbound/outbound transports.
// It is typically created by using aries.Context().
type Provider interface {
	InboundMessageHandler() InboundMessageHandler
	Packager() transport.Packager
	AriesFrameworkID() string
}

// InboundTransport interface definition for inbound transport layer
type InboundTransport interface {
	// starts the inbound transport
	Start(prov Provider) error

	// stops the inbound transport
	Stop() error

	// returns the endpoint
	Endpoint() string
}
