/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

// Handler provides protocol service handle api.
type Handler interface {
	Handle(msg *DIDCommMsg) error
}

// DIDComm defines service APIs.
type DIDComm interface {
	// service handler
	Handler

	// event service
	Event
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
	// ToVerKeys are recipient keys
	ToVerKeys []string
}

// Destination provides the recipientKeys, routingKeys, and serviceEndpoint populated from Invitation
type Destination struct {
	RecipientKeys   []string
	ServiceEndpoint string
	RoutingKeys     []string
}
