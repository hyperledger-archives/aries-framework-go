/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dispatcher

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

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
	// TODO : might need refactor as per the issue-226
	OutboundDestination *Destination
}

// Destination provides the recipientKeys, routingKeys, and serviceEndpoint populated from Invitation
type Destination struct {
	RecipientKeys   []string
	ServiceEndpoint string
	RoutingKeys     []string
}

// Outbound interface
type Outbound interface {
	Send(interface{}, string, *Destination) error
}

// Provider interface for outbound ctx
type Provider interface {
	PackWallet() wallet.Pack
	OutboundTransports() []transport.OutboundTransport
}

// OutboundCreator method to create new outbound dispatcher service
type OutboundCreator func(prov Provider) (Outbound, error)

// DIDCommAction message type to pass events in go channels.
type DIDCommAction struct {
	// DIDComm message
	Message DIDCommMsg
	// Callback function to be called by the consumer for further processing the message.
	Callback Callback
}

// DIDCommCallback message type to pass service callback in go channels.
type DIDCommCallback struct {
	// Set the value in case of any error while processing the DIDComm message event by the consumer.
	Err error
}

// Callback type to pass service callbacks.
type Callback func(DIDCommCallback)
