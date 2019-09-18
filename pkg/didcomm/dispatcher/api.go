/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

import "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"

// Service protocol service
type Service interface {
	Handle(msg DIDCommMsg) error
	Accept(msgType string) bool
	Name() string
}

// DIDCommMsg did comm msg
type DIDCommMsg struct {
	// Outbound indicates the direction of this DIDComm message:
	//   - outgoing (to another agent)
	//   - incoming (from another agent)
	Outbound bool
	Type     string
	Payload  []byte
}

// Destination provides the recipientKeys, routingKeys, and serviceEndpoint populated from Invitation
type Destination struct {
	RecipientKeys   []string
	ServiceEndpoint string
	RoutingKeys     []string
}

// Outbound interface
type Outbound interface {
	Send(interface{}, *Destination) error
}

// OutboundCreator method to create new outbound dispatcher service
type OutboundCreator func(outboundTransports []transport.OutboundTransport) (Outbound, error)
