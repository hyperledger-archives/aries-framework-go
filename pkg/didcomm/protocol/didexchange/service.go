/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/base64"
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/common/metadata"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
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
	ProtocolConfig() api.ProtocolConfig
}

// config interface
type config interface {
	AgentLabel() string
	AgentServiceEndpoint() string
}

// Service for DID exchange protocol
type Service struct {
	outboundTransport transport.OutboundTransport
	store             storage.Store
	config            config
}

// New return didexchange service
func New(store storage.Store, prov provider) *Service {
	return &Service{outboundTransport: prov.OutboundTransport(), store: store, config: prov.ProtocolConfig()}
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
func (s *Service) CreateInvitation() (*InvitationRequest, error) {
	return &InvitationRequest{Invitation: &Invitation{
		Type:            connectionInvite,
		ID:              uuid.New().String(),
		Label:           s.config.AgentLabel(),
		RecipientKeys:   nil, //TODO #178
		ServiceEndpoint: s.config.AgentServiceEndpoint(),
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
