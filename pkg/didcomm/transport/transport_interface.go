/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package transport

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

// OutboundTransport interface definition for transport layer
// This is the client side of the agent.
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

// Envelope holds message data and metadata for inbound and outbound messaging.
type Envelope struct {
	MediaTypeProfile string
	Message          []byte
	FromKey          []byte
	// ToKeys stores keys for an outbound message packing
	ToKeys []string
	// ToKey holds the key that was used to decrypt an inbound message
	ToKey []byte
}

// InboundMessageHandler handles the inbound requests. The transport will unpack the payload prior to the
// message handle invocation.
type InboundMessageHandler func(envelope *Envelope) error

// Provider contains dependencies for starting the inbound/outbound transports.
// It is typically created by using aries.Context().
type Provider interface {
	InboundMessageHandler() InboundMessageHandler
	Packager() Packager
	AriesFrameworkID() string
}

// InboundTransport interface definition for inbound transport layer.
type InboundTransport interface {
	// starts the inbound transport
	Start(prov Provider) error

	// stops the inbound transport
	Stop() error

	// returns the endpoint
	Endpoint() string
}

// Packager manages the handling, building and parsing of DIDComm raw messages in JSON envelopes.
//
// These envelopes are used as wire-level wrappers of messages sent in Aries agent-agent communication.
type Packager interface {
	// PackMessage Pack a message for one or more recipients.
	//
	// Args:
	//
	// envelope: The message to pack
	//
	// Returns:
	//
	// []byte: The packed message
	//
	// error: error
	PackMessage(envelope *Envelope) ([]byte, error)

	// UnpackMessage Unpack a message.
	//
	// Args:
	//
	// encMessage: The encrypted message
	//
	// Returns:
	//
	// envelope: unpack message
	//
	// error: error
	UnpackMessage(encMessage []byte) (*Envelope, error)
}
