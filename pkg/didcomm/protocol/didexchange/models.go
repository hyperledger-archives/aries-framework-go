/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// OOBInvitation to connect with did-exchange.
type OOBInvitation struct {
	// ID of this invitation (for record-keeping purposes).
	// TODO can we remove this?
	ID string
	// TODO remove this
	Type string `json:"@type"`
	// ID of the thread from which this invitation originated.
	// This will become the parent thread ID of the didexchange protocol instance.
	ThreadID string
	// Label of the connection invitation.
	Label string
	// Target destination.
	// This can be any on of:
	// - a string with a valid DID
	// - a valid `did.Service`
	Target interface{}
}

// Invitation model
//
// Invitation defines DID exchange invitation message
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange#0-invitation-to-exchange
//
// TODO all uses of this invitation struct should be replaced with the new OOB one. The new one should be renamed
//  to 'Invitation'.
type Invitation struct {
	// the Image URL of the connection invitation
	ImageURL string `json:"imageUrl,omitempty"`

	// the Service endpoint of the connection invitation
	ServiceEndpoint string `json:"serviceEndpoint,omitempty"`

	// the RecipientKeys for the connection invitation
	RecipientKeys []string `json:"recipientKeys,omitempty"`

	// the ID of the connection invitation
	ID string `json:"@id,omitempty"`

	// the Label of the connection invitation
	Label string `json:"label,omitempty"`

	// the DID of the connection invitation
	DID string `json:"did,omitempty"`

	// the RoutingKeys of the connection invitation
	RoutingKeys []string `json:"routingKeys,omitempty"`

	// the Type of the connection invitation
	Type   string            `json:"@type,omitempty"`
	Thread *decorator.Thread `json:"~thread,omitempty"`
}

// Request defines a2a DID exchange request
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange#1-exchange-request
type Request struct {
	Type       string            `json:"@type,omitempty"`
	ID         string            `json:"@id,omitempty"`
	Label      string            `json:"label,omitempty"`
	Connection *Connection       `json:"connection,omitempty"`
	Thread     *decorator.Thread `json:"~thread,omitempty"`
}

// Response defines a2a DID exchange response
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange#2-exchange-response
type Response struct {
	Type                string               `json:"@type,omitempty"`
	ID                  string               `json:"@id,omitempty"`
	ConnectionSignature *ConnectionSignature `json:"connection~sig,omitempty"`
	Thread              *decorator.Thread    `json:"~thread,omitempty"`
}

// ConnectionSignature connection signature
type ConnectionSignature struct {
	Type       string `json:"@type,omitempty"`
	Signature  string `json:"signature,omitempty"`
	SignedData string `json:"sig_data,omitempty"`
	SignVerKey string `json:"signers,omitempty"`
}

// Connection connection
type Connection struct {
	DID    string   `json:"did,omitempty"`
	DIDDoc *did.Doc `json:"did_doc,omitempty"`
}
