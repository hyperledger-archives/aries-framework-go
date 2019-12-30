/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// Invitation model
//
// Invitation defines DID exchange invitation message
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange#0-invitation-to-exchange
//
type Invitation struct {
	service.Header
	// the Image URL of the connection invitation
	ImageURL string `json:"imageUrl,omitempty"`

	// the Service endpoint of the connection invitation
	ServiceEndpoint string `json:"serviceEndpoint,omitempty"`

	// the RecipientKeys for the connection invitation
	RecipientKeys []string `json:"recipientKeys,omitempty"`

	// the Label of the connection invitation
	Label string `json:"label,omitempty"`

	// the DID of the connection invitation
	DID string `json:"did,omitempty"`

	// the RoutingKeys of the connection invitation
	RoutingKeys []string `json:"routingKeys,omitempty"`
}

// Request defines a2a DID exchange request
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange#1-exchange-request
type Request struct {
	service.Header
	Label      string      `json:"label,omitempty"`
	Connection *Connection `json:"connection,omitempty"`
}

// Response defines a2a DID exchange response
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange#2-exchange-response
type Response struct {
	service.Header
	ConnectionSignature *ConnectionSignature `json:"connection~sig,omitempty"`
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
