/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/base64"
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"

	"github.com/hyperledger/aries-framework-go/pkg/storage"

	"github.com/hyperledger/aries-framework-go/pkg/common/metadata"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	errors "golang.org/x/xerrors"
)

const (
	// DIDExchange did exchange protocol
	DIDExchange        = "didexchange"
	connectionSpec     = metadata.AriesCommunityDID + ";spec/connections/1.0/"
	connectionInvite   = connectionSpec + "invitation"
	connectionRequest  = connectionSpec + "request"
	connectionResponse = connectionSpec + "response"
)

// provider contains dependencies for the DID exchange protocol and is typically created by using aries.Context()
type provider interface {
	OutboundTransport() transport.OutboundTransport
}

// Service for DID exchange protocol
type Service struct {
	outboundTransport transport.OutboundTransport
	store             storage.Store
}

// New return didexchange service
func New(store storage.Store, prov provider) *Service {
	return &Service{outboundTransport: prov.OutboundTransport(), store: store}
}

// Handle didexchange msg
func (s *Service) Handle(msg dispatcher.DIDCommMsg) error {
	// TODO add Handle logic
	return nil
}

// Accept msg
func (s *Service) Accept(msgType string) bool {
	// TODO add Accept logic
	// for now return true
	return true
}

// Name return service name
func (s *Service) Name() string {
	return DIDExchange
}

// Connection return connection
func (s *Service) Connection(id string) {
	// TODO add Connection logic

}

// Connections return all connections
func (s *Service) Connections() {
	// TODO add Connections logic

}

// SendExchangeRequest sends exchange request
func (s *Service) SendExchangeRequest(exchangeRequest *Request, destination string) error {
	if exchangeRequest == nil {
		return errors.New("exchangeRequest cannot be nil")
	}

	exchangeRequest.Type = connectionRequest

	// ignore response data as it is not used in this communication mode as defined in the spec
	_, err := s.marshalAndSend(exchangeRequest, "Error Marshalling Exchange Request", destination)
	return err
}

// SendExchangeResponse sends exchange response
func (s *Service) SendExchangeResponse(exchangeResponse *Response, destination string) error {
	if exchangeResponse == nil {
		return errors.New("exchangeResponse cannot be nil")
	}

	exchangeResponse.Type = connectionResponse

	// ignore response data as it is not used in this communication mode as defined in the spec
	_, err := s.marshalAndSend(exchangeResponse, "Error Marshalling Exchange Response", destination)
	return err
}

//CreateInvitation creates invitation
//TODO to be implemented
func (s *Service) CreateInvitation() (*CreateInvitationResponse, error) {
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

func (s *Service) marshalAndSend(data interface{}, errorMsg, destination string) (string, error) {
	jsonString, err := json.Marshal(data)
	if err != nil {
		return "", errors.Errorf("%s : %w", errorMsg, err)
	}
	return s.outboundTransport.Send(string(jsonString), destination)
}

func encodedExchangeInvitation(inviteMessage *Invitation) (string, error) {
	inviteMessage.Type = connectionInvite

	invitationJSON, err := json.Marshal(inviteMessage)
	if err != nil {
		return "", errors.Errorf("JSON Marshal Error : %w", err)
	}

	return base64.URLEncoding.EncodeToString(invitationJSON), nil
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
