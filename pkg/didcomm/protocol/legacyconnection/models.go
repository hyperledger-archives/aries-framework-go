/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package legacyconnection

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/mitchellh/mapstructure"

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

type legacyConnection struct {
	DID    string     `json:"DID,omitempty"`
	DIDDoc *legacyDoc `json:"DIDDoc,omitempty"`
}

type legacyDoc struct {
	Context              interface{}              `json:"@context,omitempty"`
	ID                   string                   `json:"id,omitempty"`
	AlsoKnownAs          []interface{}            `json:"alsoKnownAs,omitempty"`
	VerificationMethod   []map[string]interface{} `json:"verificationMethod,omitempty"`
	PublicKey            []map[string]interface{} `json:"publicKey,omitempty"`
	Service              []map[string]interface{} `json:"service,omitempty"`
	Authentication       []interface{}            `json:"authentication,omitempty"`
	AssertionMethod      []interface{}            `json:"assertionMethod,omitempty"`
	CapabilityDelegation []interface{}            `json:"capabilityDelegation,omitempty"`
	CapabilityInvocation []interface{}            `json:"capabilityInvocation,omitempty"`
	KeyAgreement         []interface{}            `json:"keyAgreement,omitempty"`
	Created              *time.Time               `json:"created,omitempty"`
	Updated              *time.Time               `json:"updated,omitempty"`
	Proof                []interface{}            `json:"proof,omitempty"`
}

// JSONBytes converts Connection to json bytes.
func (con *Connection) toLegacyJSONBytes() ([]byte, error) {
	if con.DIDDoc == nil {
		return nil, fmt.Errorf("DIDDoc field cannot be empty")
	}

	legDoc, err := con.DIDDoc.ToLegacyRawDoc()
	if err != nil {
		return nil, fmt.Errorf("converting to Legacy Raw Doc failed: %w", err)
	}

	connDoc := &legacyDoc{}

	_ = mapstructure.Decode(legDoc, connDoc) //nolint: errcheck

	conRaw := legacyConnection{
		DID:    con.DID,
		DIDDoc: connDoc,
	}

	byteConn, err := json.Marshal(conRaw)
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of connection raw failed: %w", err)
	}

	return byteConn, nil
}

// ParseConnection creates an instance of Connection by reading a JSON connection from bytes.
func parseLegacyJSONBytes(data []byte) (*Connection, error) {
	connRaw := &legacyConnection{}

	err := json.Unmarshal(data, &connRaw)
	if err != nil {
		return nil, fmt.Errorf("JSON umarshalling of connection data bytes failed: %w", err)
	} else if connRaw.DIDDoc == nil {
		return nil, errors.New("connection DIDDoc field is missed")
	}

	docRaw, err := json.Marshal(connRaw.DIDDoc)
	if err != nil {
		return nil, fmt.Errorf("JSON marshaling failed: %w", err)
	}

	doc, err := did.ParseDocument(docRaw)
	if err != nil {
		return nil, fmt.Errorf("parcing did document failed: %w", err)
	}

	return &Connection{
		DID:    connRaw.DID,
		DIDDoc: doc,
	}, nil
}
