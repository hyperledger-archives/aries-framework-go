/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// constants for route coordination spec types
const (
	// Coordination route coordination protocol
	Coordination = "routecoordination"

	// RouteCoordinationSpec defines the route coordination spec
	CoordinationSpec = "https://didcomm.org/routecoordination/1.0/"

	// RouteRequestMsgType defines the route coordination request message type.
	RequestMsgType = CoordinationSpec + "route-request"

	// RouteGrantMsgType defines the route coordination request grant message type.
	GrantMsgType = CoordinationSpec + "route-grant"

	// KeyListUpdateMsgType defines the route coordination key list update message type.
	KeyListUpdateMsgType = CoordinationSpec + "keylist_update"

	// KeyListUpdateResponseMsgType defines the route coordination key list update message response type.
	KeyListUpdateResponseMsgType = CoordinationSpec + "keylist_update_response"
)

// provider contains dependencies for the Routing protocol and is typically created by using aries.Context()
type provider interface {
	OutboundDispatcher() dispatcher.Outbound
	StorageProvider() storage.Provider
	InboundTransportEndpoint() string
	KMS() kms.KeyManager
}

// Service for Route Coordination protocol.
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0211-route-coordination
type Service struct {
	service.Action
	service.Message
	routeStore storage.Store
	outbound   dispatcher.Outbound
	endpoint   string
	kms        kms.KeyManager
}

// New return route coordination service.
func New(prov provider) (*Service, error) {
	store, err := prov.StorageProvider().OpenStore(Coordination)
	if err != nil {
		return nil, fmt.Errorf("open route coordination store : %w", err)
	}

	return &Service{
		routeStore: store,
		outbound:   prov.OutboundDispatcher(),
		endpoint:   prov.InboundTransportEndpoint(),
		kms:        prov.KMS(),
	}, nil
}

// HandleInbound handles inbound route coordination messages.
func (s *Service) HandleInbound(msg *service.DIDCommMsg) (string, error) {
	return "", errors.New("not implemented")
}

// HandleOutbound handles outbound route coordination messages.
func (s *Service) HandleOutbound(msg *service.DIDCommMsg, destination *service.Destination) error {
	return errors.New("not implemented")
}

// Accept checks whether the service can handle the message type.
func (s *Service) Accept(msgType string) bool {
	switch msgType {
	case RequestMsgType, GrantMsgType, KeyListUpdateMsgType, KeyListUpdateResponseMsgType:
		return true
	}

	return false
}

// Name of the service
func (s *Service) Name() string {
	return Coordination
}
