/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/base64"
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/common/metadata"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	errors "golang.org/x/xerrors"
)

const (
	connectionSpec     = metadata.AriesCommunityDID + ";spec/connections/1.0/"
	connectionInvite   = connectionSpec + "invitation"
	connectionRequest  = connectionSpec + "request"
	connectionResponse = connectionSpec + "response"
)

// provider contains dependencies for the DID exchange protocol and is typically created by using aries.Context()
type provider interface {
	OutboundTransport() transport.OutboundTransport
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

// Protocol for DID exchange protocol
type Protocol struct {
	outboundTransport transport.OutboundTransport
}

// New instanstiated new exchange client
// The argument takes a implementation of transport.OutboundTransport (dependencies required for DID Exchange protocol) and
// this is typically called by using aries.Context()
func New(prov provider) *Protocol {
	return &Protocol{prov.OutboundTransport()}
}

// SendExchangeRequest sends exchange request
func (p *Protocol) SendExchangeRequest(exchangeRequest *Request, destination string) error {
	if exchangeRequest == nil {
		return errors.New("exchangeRequest cannot be nil")
	}

	exchangeRequest.Type = connectionRequest

	// ignore response data as it is not used in this communication mode as defined in the spec
	_, err := p.marshalAndSend(exchangeRequest, "Error Marshalling Exchange Request", destination)
	return err
}

// SendExchangeResponse sends exchange response
func (p *Protocol) SendExchangeResponse(exchangeResponse *Response, destination string) error {
	if exchangeResponse == nil {
		return errors.New("exchangeResponse cannot be nil")
	}

	exchangeResponse.Type = connectionResponse

	// ignore response data as it is not used in this communication mode as defined in the spec
	_, err := p.marshalAndSend(exchangeResponse, "Error Marshalling Exchange Response", destination)
	return err
}

//CreateInvitation creates invitation
//TODO to be implemented
func (p *Protocol) CreateInvitation() (*CreateInvitationResponse, error) {
	//TODO given below is sample response
	return &CreateInvitationResponse{
		Invitation: &InvitationRequest{
			ID:  "3a132aff-8968-4ed5-8142-776d4ff7cbb4",
			URL: "http://sampleeurl?c_i=eyJAdHlwZSI6ICJkaWQ6c292OkJ6Q",
			Invitation: &Invitation{
				ID:    "45e01a60-73e4-4ce5-891e-c0dfdda01d40",
				Label: "Sample Agent",
			},
		},
	}, nil
}

func encodedExchangeInvitation(inviteMessage *Invitation) (string, error) {
	inviteMessage.Type = connectionInvite

	invitationJSON, err := json.Marshal(inviteMessage)
	if err != nil {
		return "", errors.Errorf("JSON Marshal Error : %w", err)
	}

	return base64.URLEncoding.EncodeToString(invitationJSON), nil
}

func (p *Protocol) marshalAndSend(data interface{}, errorMsg, destination string) (string, error) {
	jsonString, err := json.Marshal(data)
	if err != nil {
		return "", errors.Errorf("%s : %w", errorMsg, err)
	}
	return p.outboundTransport.Send(string(jsonString), destination)
}
