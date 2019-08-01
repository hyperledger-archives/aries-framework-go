/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package exchange

import (
	"encoding/base64"
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/common/metadata"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	errors "golang.org/x/xerrors"
)

const (
	connectionSpec     = metadata.AriesCommunityDID + ";spec/connections/1.0/"
	connectionInvite   = connectionSpec + "invitation"
	connectionRequest  = connectionSpec + "request"
	connectionResponse = connectionSpec + "response"
)

// Invitation defines DID exchange invitation message
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange#0-invitation-to-exchange
type Invitation struct {
	Type            string   `json:"@type,omitempty"`
	ID              string   `json:"@id,omitempty"`
	Label           string   `json:"label,omitempty"`
	DID             string   `json:"did,omitempty"`
	RecipientKeys   []string `json:"recipientKeys,omitempty"`
	ServiceEndpoint string   `json:"serviceEndpoint,omitempty"`
	RoutingKeys     []string `json:"routingKeys,omitempty"`
}

// Request defines a2a DID exchange request
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0023-did-exchange#1-exchange-request
type Request struct {
	Type       string      `json:"@type,omitempty"`
	ID         string      `json:"@id,omitempty"`
	Label      string      `json:"label,omitempty"`
	Connection *Connection `json:"connection,omitempty"`
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

// GenerateInviteWithPublicDID generates the DID exchange invitation string with public DID
func GenerateInviteWithPublicDID(invite *Invitation) (string, error) {
	if invite.ID == "" || invite.DID == "" {
		return "", errors.New("ID and DID are mandatory")
	}

	return encodedExchangeInvitation(invite)
}

// GenerateInviteWithKeyAndEndpoint generates the DID exchange invitation string with recipient key and endpoint
func GenerateInviteWithKeyAndEndpoint(invite *Invitation) (string, error) {
	if invite.ID == "" || invite.ServiceEndpoint == "" || len(invite.RecipientKeys) == 0 {
		return "", errors.New("ID, Service Endpoint and Recipient Key are mandatory")
	}

	return encodedExchangeInvitation(invite)
}

// SendExchangeRequest sends exchange request
func SendExchangeRequest(exchangeRequest *Request, destination string, transport transport.OutboundTransport) error {
	if exchangeRequest == nil {
		return errors.New("exchangeRequest cannot be nil")
	}

	exchangeRequest.Type = connectionRequest

	// ignore response data as it is not used in this communication mode as defined in the spec
	_, err := marshalAndSend(exchangeRequest, "Error Marshalling Exchange Request", destination, transport)
	return err
}

// SendExchangeResponse sends exchange response
func SendExchangeResponse(exchangeResponse *Response, destination string, transport transport.OutboundTransport) error {
	if exchangeResponse == nil {
		return errors.New("exchangeResponse cannot be nil")
	}

	exchangeResponse.Type = connectionResponse

	// ignore response data as it is not used in this communication mode as defined in the spec
	_, err := marshalAndSend(exchangeResponse, "Error Marshalling Exchange Response", destination, transport)
	return err
}

func encodedExchangeInvitation(inviteMessage *Invitation) (string, error) {
	inviteMessage.Type = connectionInvite

	invitationJSON, err := json.Marshal(inviteMessage)
	if err != nil {
		return "", errors.Errorf("JSON Marshal Error : %w", err)
	}

	return base64.URLEncoding.EncodeToString(invitationJSON), nil
}

func marshalAndSend(data interface{}, errorMsg, destination string, transport transport.OutboundTransport) (string, error) {
	jsonString, err := json.Marshal(data)
	if err != nil {
		return "", errors.Errorf("%s : %w", errorMsg, err)
	}
	return transport.Send(string(jsonString), destination)
}
