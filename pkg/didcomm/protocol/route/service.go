/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
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

const (
	// data key to store router connection ID
	routeConnIDDataKey = "route-connID"
)

// ErrConnectionNotFound connection not found error
var ErrConnectionNotFound = errors.New("connection not found")

// provider contains dependencies for the Routing protocol and is typically created by using aries.Context()
type provider interface {
	OutboundDispatcher() dispatcher.Outbound
	StorageProvider() storage.Provider
	TransientStorageProvider() storage.Provider
	InboundTransportEndpoint() string
	KMS() legacykms.KeyManager
	VDRIRegistry() vdri.Registry
}

// Service for Route Coordination protocol.
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0211-route-coordination
type Service struct {
	service.Action
	service.Message
	routeStore               storage.Store
	connectionLookup         *connection.Lookup
	outbound                 dispatcher.Outbound
	endpoint                 string
	kms                      legacykms.KeyManager
	vdRegistry               vdri.Registry
	routeRegistrationMap     map[string]chan Grant
	routeRegistrationMapLock sync.RWMutex
	keylistUpdateMap         map[string]chan *KeylistUpdateResponse
	keylistUpdateMapLock     sync.RWMutex
}

// New return route coordination service.
func New(prov provider) (*Service, error) {
	store, err := prov.StorageProvider().OpenStore(Coordination)
	if err != nil {
		return nil, fmt.Errorf("open route coordination store : %w", err)
	}

	connectionLookup, err := connection.NewLookup(prov)
	if err != nil {
		return nil, err
	}

	return &Service{
		routeStore:           store,
		outbound:             prov.OutboundDispatcher(),
		endpoint:             prov.InboundTransportEndpoint(),
		kms:                  prov.KMS(),
		vdRegistry:           prov.VDRIRegistry(),
		connectionLookup:     connectionLookup,
		routeRegistrationMap: make(map[string]chan Grant),
		keylistUpdateMap:     make(map[string]chan *KeylistUpdateResponse),
	}, nil
}

// HandleInbound handles inbound route coordination messages.
func (s *Service) HandleInbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) { // nolint gocyclo (5 switch cases)
	// perform action on inbound message asynchronously
	go func() {
		switch msg.Type() {
		case RequestMsgType:
			if err := s.handleRequest(msg, myDID, theirDID); err != nil {
				logger.Errorf("handle route request error : %s", err)
			}
		case GrantMsgType:
			if err := s.handleGrant(msg); err != nil {
				logger.Errorf("handle route grant error : %s", err)
			}
		case KeylistUpdateMsgType:
			if err := s.handleKeylistUpdate(msg, myDID, theirDID); err != nil {
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

	return msg.ID(), nil
}

// HandleOutbound handles outbound route coordination messages.
func (s *Service) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) error {
	return errors.New("not implemented")
}

// SendRequest send route request
func (s *Service) SendRequest(myDID, theirDID string) (string, error) {
	// send the request
	req := &Request{
		ID:   uuid.New().String(),
		Type: RequestMsgType,
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

func (s *Service) handleRequest(msg service.DIDCommMsg, myDID, theirDID string) error {
	// unmarshal the payload
	request := &Request{}

	err := msg.Decode(request)
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
		Type:        GrantMsgType,
		ID:          msg.ID(),
		Endpoint:    s.endpoint,
		RoutingKeys: []string{sigPubKey},
	}

	return s.outbound.SendToDID(grant, myDID, theirDID)
}

func (s *Service) handleGrant(msg service.DIDCommMsg) error {
	// unmarshal the payload
	grantMsg := &Grant{}

	err := msg.Decode(grantMsg)
	if err != nil {
		return fmt.Errorf("route grant message unmarshal : %w", err)
	}

	// check if there are any channels registered for the message ID
	grantCh := s.getRouteRegistrationCh(grantMsg.ID)

	if grantCh != nil {
		// invoke the channel for the incoming message
		grantCh <- *grantMsg
	}

	return nil
}

func (s *Service) handleKeylistUpdate(msg service.DIDCommMsg, myDID, theirDID string) error {
	// unmarshal the payload
	keyUpdate := &KeylistUpdate{}

	err := msg.Decode(keyUpdate)
	if err != nil {
		return fmt.Errorf("route key list update message unmarshal : %w", err)
	}

	var updates []UpdateResponse

	// update the db
	for _, v := range keyUpdate.Updates {
		if v.Action == add {
			val := theirDID
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
		Type:    KeylistUpdateResponseMsgType,
		ID:      msg.ID(),
		Updated: updates,
	}

	return s.outbound.SendToDID(updateResponse, myDID, theirDID)
}

func (s *Service) handleKeylistUpdateResponse(msg service.DIDCommMsg) error {
	// unmarshal the payload
	respMsg := &KeylistUpdateResponse{}

	err := msg.Decode(respMsg)
	if err != nil {
		return fmt.Errorf("route keylist update response message unmarshal : %w", err)
	}

	// check if there are any channels registered for the message ID
	keylistUpdateCh := s.getKeyUpdateResponseCh(respMsg.ID)

	if keylistUpdateCh != nil {
		// invoke the channel for the incoming message
		keylistUpdateCh <- respMsg
	}

	return nil
}

func (s *Service) handleForward(msg service.DIDCommMsg) error {
	// unmarshal the payload
	forward := &Forward{}

	err := msg.Decode(forward)
	if err != nil {
		return fmt.Errorf("forward message unmarshal : %w", err)
	}

	// TODO Open question - https://github.com/hyperledger/aries-framework-go/issues/965 Mismatch between Route
	//  Coordination and Forward RFC. For now assume, the TO field contains the recipient key.
	theirDID, err := s.routeStore.Get(dataKey(forward.To))
	if err != nil {
		return fmt.Errorf("route key fetch : %w", err)
	}

	dest, err := service.GetDestination(string(theirDID), s.vdRegistry)
	if err != nil {
		return fmt.Errorf("get destination : %w", err)
	}

	return s.outbound.Forward(forward.Msg, dest)
}

// Register registers the agent with the router on the other end of the connection identified by
// connectionID. This method blocks until a response is received from the router or it times out.
// The agent is registered with the router and retrieves the router endpoint and routing keys.
// This function throws an error if the agent is already registered against a router.
// TODO https://github.com/hyperledger/aries-framework-go/issues/1076 Register agent with
//  multiple routers
func (s *Service) Register(connectionID string) error {
	// check if router is already registered
	routerConnID, err := s.getRouterConnectionID()
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
		return fmt.Errorf("fetch router connection id : %w", err)
	}

	if routerConnID != "" {
		return errors.New("router is already registered")
	}

	// get the connection record for the ID to fetch DID information
	conn, err := s.getConnection(connectionID)
	if err != nil {
		return err
	}

	// generate message ID
	msgID := uuid.New().String()

	// register chan for callback processing
	grantCh := make(chan Grant)
	s.setRouteRegistrationCh(msgID, grantCh)

	// create request message
	req := &Request{
		ID:   msgID,
		Type: RequestMsgType,
	}

	// send message to the router
	if err := s.outbound.SendToDID(req, conn.MyDID, conn.TheirDID); err != nil {
		return fmt.Errorf("send route request: %w", err)
	}

	// callback processing (to make this function look like a sync function)
	select {
	case <-grantCh:
		// TODO https://github.com/hyperledger/aries-framework-go/issues/948 save router endpoint and routing keys
	// TODO https://github.com/hyperledger/aries-framework-go/issues/948 configure this timeout at decorator level
	case <-time.After(5 * time.Second):
		return errors.New("timeout waiting for grant from the router")
	}

	// remove the channel once its been processed
	s.setRouteRegistrationCh(msgID, nil)

	// save the connectionID of the router
	return s.saveRouterConnectionID(connectionID)
}

// AddKey adds a recKey of the agent to the registered router. This method blocks until a response is
// received from the router or it times out.
// TODO https://github.com/hyperledger/aries-framework-go/issues/1076 Support for multiple routers
func (s *Service) AddKey(recKey string) error {
	// check if router is already registered
	routerConnID, err := s.getRouterConnectionID()
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
		return fmt.Errorf("fetch router connection id : %w", err)
	}

	if routerConnID == "" {
		return errors.New("router not registered")
	}

	// get the connection record for the ID to fetch DID information
	conn, err := s.getConnection(routerConnID)
	if err != nil {
		return err
	}

	// generate message ID
	msgID := uuid.New().String()

	// register chan for callback processing
	keyUpdateCh := make(chan *KeylistUpdateResponse)
	s.setKeyUpdateResponseCh(msgID, keyUpdateCh)

	keyUpdate := &KeylistUpdate{
		ID:   msgID,
		Type: KeylistUpdateMsgType,
		Updates: []Update{
			{
				RecipientKey: recKey,
				Action:       add,
			},
		},
	}

	if err := s.outbound.SendToDID(keyUpdate, conn.MyDID, conn.TheirDID); err != nil {
		return fmt.Errorf("send route request: %w", err)
	}

	select {
	case keyUpdateResp := <-keyUpdateCh:
		if err := processKeylistUpdateResp(recKey, keyUpdateResp); err != nil {
			return err
		}
	// TODO https://github.com/hyperledger/aries-framework-go/issues/948 configure this timeout at decorator level
	case <-time.After(5 * time.Second):
		return errors.New("timeout waiting for keylist update response from the router")
	}

	// remove the channel once its been processed
	s.setRouteRegistrationCh(msgID, nil)

	return nil
}

func processKeylistUpdateResp(recKey string, keyUpdateResp *KeylistUpdateResponse) error {
	for _, result := range keyUpdateResp.Updated {
		if result.RecipientKey == recKey && result.Action == add && result.Result != success {
			return errors.New("failed to update the recipient key with the router")
		}
	}

	return nil
}

func (s *Service) getRouteRegistrationCh(msgID string) chan Grant {
	s.routeRegistrationMapLock.RLock()
	defer s.routeRegistrationMapLock.RUnlock()

	return s.routeRegistrationMap[msgID]
}

func (s *Service) setRouteRegistrationCh(msgID string, grantCh chan Grant) {
	s.routeRegistrationMapLock.Lock()
	defer s.routeRegistrationMapLock.Unlock()

	if grantCh == nil {
		delete(s.routeRegistrationMap, msgID)
	} else {
		s.routeRegistrationMap[msgID] = grantCh
	}
}

func (s *Service) getKeyUpdateResponseCh(msgID string) chan *KeylistUpdateResponse {
	s.keylistUpdateMapLock.RLock()
	defer s.keylistUpdateMapLock.RUnlock()

	return s.keylistUpdateMap[msgID]
}

func (s *Service) setKeyUpdateResponseCh(msgID string, keyUpdateCh chan *KeylistUpdateResponse) {
	s.keylistUpdateMapLock.Lock()
	defer s.keylistUpdateMapLock.Unlock()

	if keyUpdateCh == nil {
		delete(s.keylistUpdateMap, msgID)
	} else {
		s.keylistUpdateMap[msgID] = keyUpdateCh
	}
}

func (s *Service) getRouterConnectionID() (string, error) {
	id, err := s.routeStore.Get(routeConnIDDataKey)
	if err != nil {
		return "", err
	}

	return string(id), nil
}

func (s *Service) saveRouterConnectionID(id string) error {
	return s.routeStore.Put(routeConnIDDataKey, []byte(id))
}

func (s *Service) getConnection(routerConnID string) (*connection.Record, error) {
	conn, err := s.connectionLookup.GetConnectionRecord(routerConnID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return nil, ErrConnectionNotFound
		}

		return nil, fmt.Errorf("fetch connection record from store : %w", err)
	}

	return conn, nil
}

func dataKey(id string) string {
	return "route-" + id
}
