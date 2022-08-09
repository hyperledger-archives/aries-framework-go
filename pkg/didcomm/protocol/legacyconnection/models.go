/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package legacyconnection

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// Invitation model
//
// Invitation defines Connection protocol invitation message
// https://github.com/hyperledger/aries-rfcs/tree/main/features/0160-connection-protocol#0-invitation-to-connect
type Invitation struct {
	// the Type of the connection invitation
	Type string `json:"@type,omitempty"`

	// the ID of the connection invitation
	ID string `json:"@id,omitempty"`

	// the Label of the connection invitation
	Label string `json:"label,omitempty"`

	// the RecipientKeys for the connection invitation
	RecipientKeys []string `json:"recipientKeys,omitempty"`

	// the Service endpoint of the connection invitation
	ServiceEndpoint string `json:"serviceEndpoint,omitempty"`

	// the RoutingKeys of the connection invitation
	RoutingKeys []string `json:"routingKeys,omitempty"`

	// the DID of the connection invitation
	DID string `json:"did,omitempty"`
}

// Request defines a2a Connection request
// https://github.com/hyperledger/aries-rfcs/tree/main/features/0160-connection-protocol#1-connection-request
type Request struct {
	Type       string            `json:"@type,omitempty"`
	ID         string            `json:"@id,omitempty"`
	Label      string            `json:"label"`
	Thread     *decorator.Thread `json:"~thread,omitempty"`
	Connection *Connection       `json:"connection,omitempty"`
}

// Response defines a2a Connection response
// https://github.com/hyperledger/aries-rfcs/tree/main/features/0160-connection-protocol#2-connection-response
type Response struct {
	Type                string               `json:"@type,omitempty"`
	ID                  string               `json:"@id,omitempty"`
	ConnectionSignature *ConnectionSignature `json:"connection~sig,omitempty"`
	Thread              *decorator.Thread    `json:"~thread,omitempty"`
	PleaseAck           *PleaseAck           `json:"~please_ack,omitempty"`
}

// ConnectionSignature connection signature.
type ConnectionSignature struct {
	Type       string `json:"@type,omitempty"`
	Signature  string `json:"signature,omitempty"`
	SignedData string `json:"sig_data,omitempty"`
	SignVerKey string `json:"signer,omitempty"`
}

// PleaseAck connection response accepted acknowledgement.
type PleaseAck struct {
	On []string `json:"on,omitempty"`
}

// Connection defines connection body of connection request.
type Connection struct {
	DID    string   `json:"DID,omitempty"`
	DIDDoc *did.Doc `json:"DIDDoc,omitempty"`
}
