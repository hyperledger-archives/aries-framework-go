/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

var logger = log.New("aries-framework/route/service")

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
	KeylistUpdateMsgType = CoordinationSpec + "keylist_update"

	// KeyListUpdateResponseMsgType defines the route coordination key list update message response type.
	KeylistUpdateResponseMsgType = CoordinationSpec + "keylist_update_response"

	// ForwardMsgType defines the route forward message type.
	ForwardMsgType = "https://didcomm.org/routing/1.0/forward"
)

// constants for key list update processing
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0211-route-coordination#keylist-update
const (
	// add key to the store
	add = "add"

	// remove key from the store
	remove = "remove"

	// server error while storing the key
	serverError = "server_error"

	// key save success
	success = "success"
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
func (s *Service) HandleInbound(msg *service.DIDCommMsg) (string, error) { // nolint gocyclo (5 switch cases)
	// perform action on inbound message asynchronously
	go func() {
		switch msg.Header.Type {
		case RequestMsgType:
			if err := s.handleRequest(msg); err != nil {
				logger.Errorf("handle route request error : %s", err)
			}
		case GrantMsgType:
			if err := s.handleGrant(msg); err != nil {
				logger.Errorf("handle route grant error : %s", err)
			}
		case KeylistUpdateMsgType:
			if err := s.handleKeylistUpdate(msg); err != nil {
				logger.Errorf("handle route keylist update error : %s", err)
			}
		case KeylistUpdateResponseMsgType:
			if err := s.handleKeylistUpdateResponse(msg); err != nil {
				logger.Errorf("handle route keylist update response error : %s", err)
			}
		case ForwardMsgType:
			if err := s.handleForward(msg); err != nil {
				logger.Errorf("handle forward error : %s", err)
			}
		}
	}()

	return msg.Header.ID, nil
}

// HandleOutbound handles outbound route coordination messages.
func (s *Service) HandleOutbound(msg *service.DIDCommMsg, destination *service.Destination) error {
	return errors.New("not implemented")
}

// SendRequest send route request
func (s *Service) SendRequest(myDID, theirDID string) (string, error) {
	// send the request
	req := &Request{
		Header: service.Header{
			ID:   uuid.New().String(),
			Type: RequestMsgType,
		},
	}

	if err := s.outbound.SendToDID(req, myDID, theirDID); err != nil {
		return "", fmt.Errorf("failed to send route request: %w", err)
	}

	return req.ID, nil
}

// Accept checks whether the service can handle the message type.
func (s *Service) Accept(msgType string) bool {
	switch msgType {
	case RequestMsgType, GrantMsgType, KeylistUpdateMsgType, KeylistUpdateResponseMsgType, ForwardMsgType:
		return true
	}

	return false
}

// Name of the service
func (s *Service) Name() string {
	return Coordination
}

func (s *Service) handleRequest(msg *service.DIDCommMsg) error {
	// unmarshal the payload
	request := &Request{}

	err := json.Unmarshal(msg.Payload, request)
	if err != nil {
		return fmt.Errorf("route request message unmarshal : %w", err)
	}

	// create keys
	_, sigPubKey, err := s.kms.CreateKeySet()
	if err != nil {
		return fmt.Errorf("failed to create keys : %w", err)
	}

	// send the grant response
	grant := &Grant{
		Header: service.Header{
			Type: GrantMsgType,
			ID:   msg.Header.ID,
		},
		Endpoint:    s.endpoint,
		RoutingKeys: []string{sigPubKey},
	}

	// TODO https://github.com/hyperledger/aries-framework-go/issues/725 get destination details from the connection
	return s.outbound.Send(grant, "", nil)
}

func (s *Service) handleGrant(msg *service.DIDCommMsg) error {
	// unmarshal the payload
	grant := &Grant{}

	err := json.Unmarshal(msg.Payload, grant)
	if err != nil {
		return fmt.Errorf("route grant message unmarshal : %w", err)
	}

	// TODO https://github.com/hyperledger/aries-framework-go/issues/948 integrate with framework components

	return nil
}

func (s *Service) handleKeylistUpdate(msg *service.DIDCommMsg) error {
	// unmarshal the payload
	keyUpdate := &KeylistUpdate{}

	err := json.Unmarshal(msg.Payload, keyUpdate)
	if err != nil {
		return fmt.Errorf("route key list update message unmarshal : %w", err)
	}

	var updates []UpdateResponse

	// update the db
	for _, v := range keyUpdate.Updates {
		if v.Action == add {
			// TODO https://github.com/hyperledger/aries-framework-go/issues/725 need to get the DID from the inbound transport
			val := ""
			result := success

			err = s.routeStore.Put(dataKey(v.RecipientKey), []byte(val))
			if err != nil {
				logger.Errorf("failed to add the route key to store : %s", err)

				result = serverError
			}

			// construct the response doc
			updates = append(updates, UpdateResponse{
				RecipientKey: v.RecipientKey,
				Action:       v.Action,
				Result:       result,
			})
		} else if v.Action == remove {
			// TODO remove from the store

			// construct the response doc
			updates = append(updates, UpdateResponse{
				RecipientKey: v.RecipientKey,
				Action:       v.Action,
				Result:       serverError,
			})
		}
	}

	// send the key update response
	updateResponse := &KeylistUpdateResponse{
		Header: service.Header{
			ID:   msg.Header.ID,
			Type: KeylistUpdateResponseMsgType,
		},
		Updated: updates,
	}

	// TODO https://github.com/hyperledger/aries-framework-go/issues/725 get destination details from the connection
	return s.outbound.Send(updateResponse, "", nil)
}

func (s *Service) handleKeylistUpdateResponse(msg *service.DIDCommMsg) error {
	// unmarshal the payload
	resp := &KeylistUpdateResponse{}

	err := json.Unmarshal(msg.Payload, resp)
	if err != nil {
		return fmt.Errorf("route keylist update response message unmarshal : %w", err)
	}

	// TODO https://github.com/hyperledger/aries-framework-go/issues/948 integrate with framework components

	return nil
}

func (s *Service) handleForward(msg *service.DIDCommMsg) error {
	// unmarshal the payload
	forward := &Forward{}

	err := json.Unmarshal(msg.Payload, forward)
	if err != nil {
		return fmt.Errorf("forward message unmarshal : %w", err)
	}

	// TODO Open question - https://github.com/hyperledger/aries-framework-go/issues/965 Mismatch between Route
	//  Coordination and Forward RFC. For now assume, the TO field contains the recipient key.
	_, err = s.routeStore.Get(dataKey(forward.To))
	if err != nil {
		return fmt.Errorf("route key fetch : %w", err)
	}

	// TODO https://github.com/hyperledger/aries-framework-go/issues/725 get destination details from the
	//  did retrieved from previous Get call.

	return s.outbound.Forward(forward.Msg, nil)
}

func dataKey(id string) string {
	return "route-" + id
}
