/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package transport

// OutboundTransport interface definition for transport layer
// This is the client side of the agent
type OutboundTransport interface {
	// Send send a2a exchange data
	Send(data string, destination string) (string, error)
}

// InboundMessageHandler handles the inbound requests. The transport will unpack the payload prior to the
// message handle invocation.
type InboundMessageHandler func(payload []byte) error
