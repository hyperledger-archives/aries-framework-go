/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/messagepickup"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/kmsdidkey"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

var logger = log.New("aries-framework/route/service")

// constants for route coordination spec types.
const (
	// Coordination route coordination protocol.
	Coordination = "coordinatemediation"

	// RouteCoordinationSpec defines the route coordination spec.
	CoordinationSpec = "https://didcomm.org/coordinatemediation/1.0/"

	// RouteRequestMsgType defines the route coordination request message type.
	RequestMsgType = CoordinationSpec + "mediate-request"

	// RouteGrantMsgType defines the route coordination request grant message type.
	GrantMsgType = CoordinationSpec + "mediate-grant"

	// KeyListUpdateMsgType defines the route coordination key list update message type.
	KeylistUpdateMsgType = CoordinationSpec + "keylist_update"

	// KeyListUpdateResponseMsgType defines the route coordination key list update message response type.
	KeylistUpdateResponseMsgType = CoordinationSpec + "keylist_update_response"
)

// constants for key list update processing
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0211-route-coordination#keylist-update
const (
	// add key to the store.
	add = "add"

	// remove key from the store.
	remove = "remove"

	// server error while storing the key.
	serverError = "server_error"

	// key save success.
	success = "success"
)

const (
	// data key to store router connection ID.
	routeConnIDDataKey = "route_connID_%s"

	// data key to store router config.
	routeConfigDataKey = "route_config_%s"

	routeGrantKey = "grant_%s"
)

const (
	updateTimeout = 10 * time.Second
)

// ErrConnectionNotFound connection not found error.
var ErrConnectionNotFound = errors.New("connection not found")

// ErrRouterNotRegistered router not registered error.
var ErrRouterNotRegistered = errors.New("router not registered")

// provider contains dependencies for the Routing protocol and is typically created by using aries.Context().
type provider interface {
	OutboundDispatcher() dispatcher.Outbound
	StorageProvider() storage.Provider
	ProtocolStateStorageProvider() storage.Provider
	RouterEndpoint() string
	KMS() kms.KeyManager
	VDRegistry() vdr.Registry
	Service(id string) (interface{}, error)
	KeyAgreementType() kms.KeyType
	MediaTypeProfiles() []string
}

// ClientOption configures the route client.
type ClientOption func(opts *ClientOptions)

// ClientOptions holds options for the router client.
type ClientOptions struct {
	Timeout time.Duration
}

// Options is a container for route protocol options.
type Options struct {
	ServiceEndpoint string
	RoutingKeys     []string
}

type callback struct {
	msg      service.DIDCommMsg
	myDID    string
	theirDID string
	options  *Options
	err      error
}

type connections interface {
	GetConnectionIDByDIDs(string, string) (string, error)
	GetConnectionRecord(string) (*connection.Record, error)
	GetConnectionRecordByDIDs(myDID string, theirDID string) (*connection.Record, error)
}

// Service for Route Coordination protocol.
// https://github.com/hyperledger/aries-rfcs/tree/master/features/0211-route-coordination
type Service struct {
	service.Action
	service.Message
	routeStore           storage.Store
	connectionLookup     connections
	outbound             dispatcher.Outbound
	endpoint             string
	kms                  kms.KeyManager
	vdRegistry           vdr.Registry
	keylistUpdateMap     map[string]chan *KeylistUpdateResponse
	keylistUpdateMapLock sync.RWMutex
	callbacks            chan *callback
	messagePickupSvc     messagepickup.ProtocolService
	keyAgreementType     kms.KeyType
	mediaTypeProfiles    []string
	initialized          bool
}

// New return route coordination service.
func New(prov provider) (*Service, error) {
	svc := Service{}

	err := svc.Initialize(prov)
	if err != nil {
		return nil, err
	}

	return &svc, nil
}

// Initialize initializes the Service. If Initialize succeeds, any further call is a no-op.
func (s *Service) Initialize(p interface{}) error {
	if s.initialized {
		return nil
	}

	prov, ok := p.(provider)
	if !ok {
		return fmt.Errorf("expected provider of type `%T`, got type `%T`", provider(nil), p)
	}

	store, err := prov.StorageProvider().OpenStore(Coordination)
	if err != nil {
		return fmt.Errorf("open route coordination store : %w", err)
	}

	err = prov.StorageProvider().SetStoreConfig(Coordination,
		storage.StoreConfiguration{TagNames: []string{routeConnIDDataKey}})
	if err != nil {
		return fmt.Errorf("failed to set store configuration: %w", err)
	}

	connectionLookup, err := connection.NewLookup(prov)
	if err != nil {
		return err
	}

	mp, err := prov.Service(messagepickup.MessagePickup)
	if err != nil {
		return err
	}

	messagePickupSvc, ok := mp.(messagepickup.ProtocolService)
	if !ok {
		return errors.New("cast service to message pickup service failed")
	}

	s.routeStore = store
	s.outbound = prov.OutboundDispatcher()
	s.endpoint = prov.RouterEndpoint()
	s.kms = prov.KMS()
	s.vdRegistry = prov.VDRegistry()
	s.connectionLookup = connectionLookup
	s.keylistUpdateMap = make(map[string]chan *KeylistUpdateResponse)
	s.callbacks = make(chan *callback)
	s.messagePickupSvc = messagePickupSvc
	s.keyAgreementType = prov.KeyAgreementType()
	s.mediaTypeProfiles = prov.MediaTypeProfiles()

	logger.Debugf("default endpoint: %s", s.endpoint)

	go s.listenForCallbacks()

	s.initialized = true

	return nil
}

func (s *Service) listenForCallbacks() {
	for c := range s.callbacks {
		logger.Debugf("handling user callback %+v with options %+v", c, c.options)

		if c.err != nil {
			go s.handleUserRejection(c)

			continue
		}

		switch c.msg.Type() {
		case RequestMsgType:
			err := s.handleInboundRequest(c)
			if err != nil {
				logger.Errorf("failed to handle inbound request: %+v : %w", c.msg, err)
			}
		default:
			logger.Warnf("ignoring unsupported message type %s", c.msg.Type())
		}
	}
}

func (s *Service) handleUserRejection(c *callback) {
	logger.Infof("user aborted response action for msgID=%s", c.msg.ID())
}

func triggersActionEvent(msgType string) bool {
	return msgType == RequestMsgType
}

func (s *Service) sendActionEvent(msg service.DIDCommMsg, myDID, theirDID string) error {
	events := s.ActionEvent()
	if events == nil {
		return fmt.Errorf("no clients registered to handle action events for %s protocol", Coordination)
	}

	logger.Debugf("dispatching action event for msg=%+v myDID=%s theirDID=%s", msg, myDID, theirDID)

	go func() {
		c := &callback{
			msg:      msg,
			myDID:    myDID,
			theirDID: theirDID,
		}

		events <- service.DIDCommAction{
			ProtocolName: Coordination,
			Message:      msg,
			Continue: func(args interface{}) {
				switch o := args.(type) {
				case Options:
					c.options = &o
				case *Options:
					c.options = o
				default:
					c.options = &Options{}
				}

				s.callbacks <- c
			},
			Stop: func(err error) {
				c.err = err

				s.callbacks <- c
			},
		}
	}()

	return nil
}

// HandleInbound handles inbound route coordination messages.
func (s *Service) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
	logger.Debugf("service.HandleInbound() input: msg=%+v myDID=%s theirDID=%s", msg, ctx.MyDID(), ctx.TheirDID())

	if triggersActionEvent(msg.Type()) {
		return msg.ID(), s.sendActionEvent(msg, ctx.MyDID(), ctx.TheirDID())
	}

	// perform action on inbound message asynchronously
	go func(msg service.DIDCommMsg) {
		var err error

		switch msg.Type() {
		case GrantMsgType:
			err = s.saveGrant(msg)
		case KeylistUpdateMsgType:
			err = s.handleKeylistUpdate(msg, ctx.MyDID(), ctx.TheirDID())
		case KeylistUpdateResponseMsgType:
			err = s.handleKeylistUpdateResponse(msg)
		case service.ForwardMsgType, service.ForwardMsgTypeV2:
			err = s.handleForward(msg)
		}

		connectionIDLog := ""

		// mediator forward messages don't have connection established with the sender; hence skip the lookup
		if msg.Type() != service.ForwardMsgType && msg.Type() != service.ForwardMsgTypeV2 {
			connectionID, connErr := s.connectionLookup.GetConnectionIDByDIDs(ctx.MyDID(), ctx.TheirDID())
			if connErr != nil {
				logutil.LogError(logger, Coordination, "connectionID lookup using DIDs", connErr.Error())
			}

			connectionIDLog = logutil.CreateKeyValueString("connectionID", connectionID)
		}

		if err != nil {
			logutil.LogError(logger, Coordination, "processMessage", err.Error(),
				logutil.CreateKeyValueString("msgType", msg.Type()),
				logutil.CreateKeyValueString("msgID", msg.ID()),
				connectionIDLog)
		} else {
			logutil.LogDebug(logger, Coordination, "processMessage", "success",
				logutil.CreateKeyValueString("msgType", msg.Type()),
				logutil.CreateKeyValueString("msgID", msg.ID()),
				connectionIDLog)
		}
	}(msg.Clone())

	return msg.ID(), nil
}

// HandleOutbound handles outbound route coordination messages.
func (s *Service) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	logger.Debugf("service.HandleOutbound input: msg=%+v myDID=%s theirDID=%s", msg, myDID, theirDID)

	if !s.Accept(msg.Type()) {
		return "", fmt.Errorf("unsupported message type %s", msg.Type())
	}

	switch msg.Type() {
	case RequestMsgType:
		return "", s.handleOutboundRequest(msg, myDID, theirDID)
	default:
		return "", fmt.Errorf("invalid or unsupported outbound message type %s", msg.Type())
	}
}

// Accept checks whether the service can handle the message type.
func (s *Service) Accept(msgType string) bool {
	switch msgType {
	case RequestMsgType, GrantMsgType, KeylistUpdateMsgType, KeylistUpdateResponseMsgType, service.ForwardMsgType,
		service.ForwardMsgTypeV2:
		return true
	}

	return false
}

// Name of the service.
func (s *Service) Name() string {
	return Coordination
}

func (s *Service) handleInboundRequest(c *callback) error {
	logger.Debugf("handling callback: %+v", c)
	logger.Debugf("options: %+v", c.options)

	// unmarshal the payload
	request := &Request{}

	err := c.msg.Decode(request)
	if err != nil {
		return fmt.Errorf("handleInboundRequest: route request message unmarshal : %w", err)
	}

	grant, err := outboundGrant(
		c.msg.ID(),
		c.options,
		s.endpoint,
		func() (string, error) {
			for _, mtp := range s.mediaTypeProfiles {
				switch mtp {
				case transport.MediaTypeDIDCommV2Profile, transport.MediaTypeAIP2RFC0587Profile:
					_, pubKeyBytes, e := s.kms.CreateAndExportPubKeyBytes(s.keyAgreementType)
					if e != nil {
						return "", fmt.Errorf("outboundGrant from handleInboundRequest: kms failed to create "+
							"and export %v key: %w", s.keyAgreementType, e)
					}

					return kmsdidkey.BuildDIDKeyByKeyType(pubKeyBytes, s.keyAgreementType)
				}
			}

			_, pubKeyBytes, er := s.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
			if er != nil {
				return "", fmt.Errorf("outboundGrant from handleInboundRequest: kms failed to create and "+
					"export ED25519 key: %w", er)
			}

			didKey, _ := fingerprint.CreateDIDKey(pubKeyBytes)

			return didKey, er
		},
	)
	if err != nil {
		return fmt.Errorf("handleInboundRequest: failed to handle inbound request : %w", err)
	}

	return s.outbound.SendToDID(service.NewDIDCommMsgMap(grant), c.myDID, c.theirDID)
}

func outboundGrant(
	msgID string, opts *Options,
	defaultEndpoint string, defaultKey func() (string, error)) (*Grant, error) {
	grant := &Grant{
		ID:          msgID,
		Type:        GrantMsgType,
		Endpoint:    opts.ServiceEndpoint,
		RoutingKeys: opts.RoutingKeys,
	}

	if grant.Endpoint == "" {
		grant.Endpoint = defaultEndpoint
	}

	if len(grant.RoutingKeys) == 0 {
		keys, err := defaultKey()
		if err != nil {
			return nil, fmt.Errorf("outboundGrant: failed to create keys : %w", err)
		}

		grant.RoutingKeys = []string{keys}
	}

	logger.Debugf("outbound grant: %+v", grant)

	return grant, nil
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

			toKey := dataKey(v.RecipientKey)

			err = s.routeStore.Put(toKey, []byte(val))
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

	return s.outbound.SendToDID(service.NewDIDCommMsgMap(updateResponse), myDID, theirDID)
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
	forward := &model.Forward{}

	err := msg.Decode(forward)
	if err != nil {
		return fmt.Errorf("forward message unmarshal : %w", err)
	}

	// TODO Open question - https://github.com/hyperledger/aries-framework-go/issues/965 Mismatch between Route
	//  Coordination and Forward RFC. For now assume, the TO field contains the recipient key (DIDComm V2 uses
	//  keyAgreement.ID, double check if this to do comment is still needed).
	toKey := dataKey(forward.To)

	theirDID, err := s.routeStore.Get(toKey)
	if err != nil {
		return fmt.Errorf("route key fetch : %w", err)
	}

	dest, err := service.GetDestination(string(theirDID), s.vdRegistry)
	if err != nil {
		return fmt.Errorf("get destination : %w", err)
	}

	err = s.outbound.Forward(forward.Msg, dest)
	if err != nil && s.messagePickupSvc != nil {
		return s.messagePickupSvc.AddMessage(forward.Msg, string(theirDID))
	}

	return err
}

// Register registers the agent with the router on the other end of the connection identified by
// connectionID. This method blocks until a response is received from the router or it times out.
// The agent is registered with the router and retrieves the router endpoint and routing keys.
// This function throws an error if the agent is already registered against a router.
func (s *Service) Register(connectionID string, options ...ClientOption) error {
	record, err := s.getConnection(connectionID)
	if err != nil {
		return fmt.Errorf("get connection: %w", err)
	}

	opts := parseClientOpts(options...)

	return s.doRegistration(
		record,
		&Request{
			Type:   RequestMsgType,
			ID:     uuid.New().String(),
			Timing: decorator.Timing{},
		},
		opts.Timeout,
	)
}

func (s *Service) doRegistration(record *connection.Record, req *Request, timeout time.Duration) error {
	// check if router is already registered
	err := s.ensureConnectionExists(record.ConnectionID)
	if err == nil {
		return errors.New("router is already registered")
	}

	if !errors.Is(err, ErrRouterNotRegistered) {
		return fmt.Errorf("ensure connection exists: %w", err)
	}

	// TODO: would this be better served as time.Now().Add(timeout).Unix() as pkg/doc/verifiable/credential.go
	// demonstrates? additionally `ExpiresTime` would need to be migrated to int64
	req.ExpiresTime = time.Now().UTC().Add(timeout)

	// send message to the router
	if err = s.outbound.SendToDID(service.NewDIDCommMsgMap(req), record.MyDID, record.TheirDID); err != nil {
		return fmt.Errorf("send route request: %w", err)
	}

	// waits until the mediate-grant message is received or timeout was exceeded
	grant, err := s.getGrant(req.ID, timeout)
	if err != nil {
		return fmt.Errorf("get grant for request ID '%s': %w", req.ID, err)
	}

	err = s.saveRouterConfig(record.ConnectionID, &config{
		RouterEndpoint: grant.Endpoint,
		RoutingKeys:    grant.RoutingKeys,
	})
	if err != nil {
		return fmt.Errorf("save route config : %w", err)
	}

	logger.Debugf("saved router config from inbound grant: %+v", grant)

	// save the connectionID of the router
	return s.saveRouterConnectionID(record.ConnectionID)
}

func (s *Service) getGrant(id string, timeout time.Duration) (*Grant, error) {
	var (
		src []byte
		err error
	)

	err = backoff.Retry(func() error {
		src, err = s.routeStore.Get(fmt.Sprintf(routeGrantKey, id))

		return err
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), uint64(timeout/time.Second)))

	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}

	var grant *Grant

	err = json.Unmarshal(src, &grant)
	if err != nil {
		return nil, fmt.Errorf("unmarshal grant: %w", err)
	}

	return grant, nil
}

func (s *Service) saveGrant(grant service.DIDCommMsg) error {
	src, err := json.Marshal(grant)
	if err != nil {
		return fmt.Errorf("marshal grant: %w", err)
	}

	return s.routeStore.Put(fmt.Sprintf(routeGrantKey, grant.ID()), src)
}

// Unregister unregisters the agent with the router.
func (s *Service) Unregister(connID string) error {
	// check if router is already registered
	err := s.ensureConnectionExists(connID)
	if err != nil {
		return fmt.Errorf("ensure connection exists: %w", err)
	}

	// TODO Remove all the recKeys from the router
	//  https://github.com/hyperledger/aries-rfcs/tree/master/features/0211-route-coordination#keylist-update-response

	// deletes the connectionID
	return s.deleteRouterConnectionID(connID)
}

// GetConnections returns the connections of the router.
func (s *Service) GetConnections() ([]string, error) {
	records, err := s.routeStore.Query(routeConnIDDataKey)
	if err != nil {
		return nil, fmt.Errorf("failed to query route store: %w", err)
	}

	defer storage.Close(records, logger)

	var conns []string

	more, err := records.Next()
	if err != nil {
		return nil, fmt.Errorf("failed to get next record: %w", err)
	}

	for more {
		value, err := records.Value()
		if err != nil {
			return nil, fmt.Errorf("failed to get value from records: %w", err)
		}

		conns = append(conns, string(value))

		more, err = records.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to get next record: %w", err)
		}
	}

	return conns, nil
}

// AddKey adds a recKey of the agent to the registered router. This method blocks until a response is
// received from the router or it times out.
// TODO https://github.com/hyperledger/aries-framework-go/issues/1076 Support for multiple routers
// TODO https://github.com/hyperledger/aries-framework-go/issues/1105 Support to Add multiple
//  recKeys to the Router
func (s *Service) AddKey(connID, recKey string) error {
	// check if router is already registered
	err := s.ensureConnectionExists(connID)
	if err != nil {
		return fmt.Errorf("ensure connection exists: %w", err)
	}

	// get the connection record for the ID to fetch DID information
	conn, err := s.getConnection(connID)
	if err != nil {
		return fmt.Errorf("get connection: %w", err)
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

	if err := s.outbound.SendToDID(service.NewDIDCommMsgMap(keyUpdate), conn.MyDID, conn.TheirDID); err != nil {
		return fmt.Errorf("send route request: %w", err)
	}

	select {
	case keyUpdateResp := <-keyUpdateCh:
		if err := processKeylistUpdateResp(recKey, keyUpdateResp); err != nil {
			return err
		}
	case <-time.After(updateTimeout):
		return errors.New("timeout waiting for keylist update response from the router")
	}

	// remove the channel once its been processed
	s.setKeyUpdateResponseCh(msgID, nil)

	return nil
}

// Config fetches the router config - endpoint and routingKeys.
func (s *Service) Config(connID string) (*Config, error) {
	// check if router is already registered
	if err := s.ensureConnectionExists(connID); err != nil {
		return nil, fmt.Errorf("ensure connection exists: %w", err)
	}

	return s.getRouterConfig(connID)
}

func processKeylistUpdateResp(recKey string, keyUpdateResp *KeylistUpdateResponse) error {
	for _, result := range keyUpdateResp.Updated {
		if result.RecipientKey == recKey && result.Action == add && result.Result != success {
			return errors.New("failed to update the recipient key with the router")
		}
	}

	return nil
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

func (s *Service) ensureConnectionExists(connID string) error {
	_, err := s.routeStore.Get(fmt.Sprintf(routeConnIDDataKey, connID))
	if errors.Is(err, storage.ErrDataNotFound) {
		return ErrRouterNotRegistered
	}

	return err
}

func (s *Service) deleteRouterConnectionID(connID string) error {
	return s.routeStore.Delete(fmt.Sprintf(routeConnIDDataKey, connID))
}

func (s *Service) saveRouterConnectionID(connID string) error {
	return s.routeStore.Put(fmt.Sprintf(routeConnIDDataKey, connID), []byte(connID), storage.Tag{Name: routeConnIDDataKey})
}

type config struct {
	RouterEndpoint string
	RoutingKeys    []string
}

func (s *Service) getRouterConfig(connID string) (*Config, error) {
	val, err := s.routeStore.Get(fmt.Sprintf(routeConfigDataKey, connID))
	if err != nil {
		return nil, fmt.Errorf("get router config data : %w", err)
	}

	conf := &config{}

	err = json.Unmarshal(val, conf)
	if err != nil {
		return nil, fmt.Errorf("unmarshal router config data : %w", err)
	}

	return NewConfig(conf.RouterEndpoint, conf.RoutingKeys), nil
}

func (s *Service) saveRouterConfig(connID string, conf *config) error {
	bytes, err := json.Marshal(conf)
	if err != nil {
		return fmt.Errorf("marshal config data: %w", err)
	}

	return s.routeStore.Put(fmt.Sprintf(routeConfigDataKey, connID), bytes)
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

func (s *Service) handleOutboundRequest(msg service.DIDCommMsg, myDID, theirDID string) error {
	req := &Request{}

	err := msg.Decode(req)
	if err != nil {
		return fmt.Errorf("failed to decode request : %w", err)
	}

	record, err := s.connectionLookup.GetConnectionRecordByDIDs(myDID, theirDID)
	if err != nil {
		return fmt.Errorf("failed to lookup connection record with myDID=%s theirDID=%s : %w",
			myDID, theirDID, err)
	}

	return s.doRegistration(record, req, updateTimeout)
}

func dataKey(id string) string {
	return "route-" + id
}

func parseClientOpts(options ...ClientOption) *ClientOptions {
	opts := &ClientOptions{
		Timeout: updateTimeout,
	}

	// generate router config from options
	for _, option := range options {
		option(opts)
	}

	return opts
}
