/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
)

var logger = log.New("aries-framework/did-exchange/service")

const (
	// Name of this protocol service.
	Name = "out-of-band"
	// RequestMsgType is the '@type' for the request message.
	RequestMsgType = "https://didcomm.org/oob-request/1.0/request"

	// TODO channel size - https://github.com/hyperledger/aries-framework-go/issues/246
	callbackChannelSize = 10
)

var errIgnoredDidEvent = errors.New("ignored")

// Service implements the Out-Of-Band protocol.
type Service struct {
	service.Action
	service.Message
	callbackChannel            chan *callback
	didSvc                     service.InboundHandler
	didEvents                  chan service.StateMsg
	store                      storage.Store
	connections                *connection.Lookup
	dispatch                   transport.InboundMessageHandler
	getNextRequestFunc         func(*myState) (*decorator.Attachment, bool)
	extractDIDCommMsgBytesFunc func(*decorator.Attachment) ([]byte, error)
	listenerFunc               func()
}

type callback struct {
	msg      service.DIDCommMsg
	myDID    string
	theirDID string
}

type myState struct {
	ID           string
	ConnectionID string
	Request      *Request
	Done         bool
}

// Provider provides this service's dependencies.
type Provider interface {
	Service(id string) (interface{}, error)
	StorageProvider() storage.Provider
	TransientStorageProvider() storage.Provider
	InboundMessageHandler() transport.InboundMessageHandler
}

// New creates a new instance of the out-of-band service.
func New(p Provider) (*Service, error) {
	svc, err := p.Service(didexchange.DIDExchange)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize outofband service : %w", err)
	}

	didSvc, ok := svc.(service.InboundHandler)
	if !ok {
		return nil, errors.New("failed to cast the didexchange service to service.InboundHandler")
	}

	store, err := p.TransientStorageProvider().OpenStore(Name)
	if err != nil {
		return nil, fmt.Errorf("failed to open the store : %w", err)
	}

	connectionLookup, err := connection.NewLookup(p)
	if err != nil {
		return nil, fmt.Errorf("failed to open a connection.Lookup : %w", err)
	}

	s := &Service{
		callbackChannel:            make(chan *callback, callbackChannelSize),
		didSvc:                     didSvc,
		didEvents:                  make(chan service.StateMsg, callbackChannelSize),
		store:                      store,
		connections:                connectionLookup,
		dispatch:                   p.InboundMessageHandler(),
		getNextRequestFunc:         getNextRequest,
		extractDIDCommMsgBytesFunc: extractDIDCommMsgBytes,
	}

	s.listenerFunc = listener(s.callbackChannel, s.didEvents, s.handleRequestCallback, s.handleDIDEvent)

	didEventsSvc, ok := didSvc.(service.Event)
	if !ok {
		return nil, errors.New("failed to cast didexchange service to service.Event")
	}

	if err = didEventsSvc.RegisterMsgEvent(s.didEvents); err != nil {
		return nil, fmt.Errorf("failed to register for didexchange protocol msgs : %w", err)
	}

	go s.listenerFunc()

	return s, nil
}

// Name is this service's name
func (s *Service) Name() string {
	return Name
}

// Accept determines whether this service can handle the given type of message
func (s *Service) Accept(msgType string) bool {
	// TODO add invitation msg type https://github.com/hyperledger/aries-rfcs/issues/451
	return msgType == RequestMsgType
}

// HandleInbound handles inbound messages
func (s *Service) HandleInbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	logger.Debugf("receive inbound message : %s", msg)

	if !s.Accept(msg.Type()) {
		return "", fmt.Errorf("unsupported message type %s", msg.Type())
	}

	// TODO should request messages with no attachments be rejected?
	//  https://github.com/hyperledger/aries-rfcs/issues/451

	go func() {
		s.ActionEvent() <- service.DIDCommAction{
			ProtocolName: Name,
			Message:      msg,
			Continue:     continueFunc(s.callbackChannel, msg, myDID, theirDID),
			Stop: func(e error) {
				// TODO noop - nothing to do here (not even cleanup)
			},
			Properties: nil,
		}
	}()

	return "", nil
}

// HandleOutbound handles outbound messages
func (s *Service) HandleOutbound(_ service.DIDCommMsg, _, _ string) error {
	// TODO implement
	return errors.New("not implemented")
}

func continueFunc(c chan *callback, msg service.DIDCommMsg, myDID, theirDID string) func(interface{}) {
	return func(_ interface{}) {
		c <- &callback{
			msg:      msg,
			myDID:    myDID,
			theirDID: theirDID,
		}
	}
}

func listener(
	callbacks chan *callback,
	didEvents chan service.StateMsg,
	handleReqFunc func(*callback) error,
	handleDidEventFunc func(msg service.StateMsg) error) func() {
	return func() {
		for {
			select {
			case c := <-callbacks:
				// TODO add support for handling the 'invitation' message
				//  https://github.com/hyperledger/aries-framework-go/issues/1488
				switch c.msg.Type() {
				case RequestMsgType:
					err := handleReqFunc(c)
					if err != nil {
						logutil.LogError(logger, Name, "handleRequestCallback", err.Error(),
							logutil.CreateKeyValueString("msgType", c.msg.Type()),
							logutil.CreateKeyValueString("msgID", c.msg.ID()))
					}
				default:
					logutil.LogError(logger, Name, "callbackChannel", "unsupported msg type",
						logutil.CreateKeyValueString("msgType", c.msg.Type()),
						logutil.CreateKeyValueString("msgID", c.msg.ID()))
				}
			case e := <-didEvents:
				err := handleDidEventFunc(e)
				if err != nil {
					logutil.LogError(logger, Name, "handleDIDEvent", err.Error())
				}
			}
		}
	}
}

func (s *Service) handleRequestCallback(c *callback) error {
	// TODO either transform to a didexchange.invitation object or refactor didexchange.Service to accept this object
	connID, err := s.didSvc.HandleInbound(c.msg, c.myDID, c.theirDID)
	if err != nil {
		return fmt.Errorf("didexchange service failed to handle inbound request : %w", err)
	}

	req := &Request{}

	err = c.msg.Decode(req)
	if err != nil {
		return fmt.Errorf("failed to decode request message : %w", err)
	}

	// TODO if we want to implement retries then we should be saving state before invoking
	//  the didexchange service
	err = s.save(&myState{
		ID:           c.msg.ID(),
		ConnectionID: connID,
		Request:      req,
	})
	if err != nil {
		return fmt.Errorf("failed to save my state : %w", err)
	}

	return nil
}

func (s *Service) handleDIDEvent(e service.StateMsg) error {
	// TODO remove 'empty parent threadID check'?
	if e.Type != service.PostState || e.Msg.Type() != didexchange.AckMsgType || e.Msg.ParentThreadID() == "" {
		// we are only interested in a successfully completed didexchange.
		// the out-of-band protocol thread should be the did-exchange's parent thread.
		return errIgnoredDidEvent
	}

	state, err := s.fetchMyState(e.Msg.ParentThreadID())
	if err != nil {
		return fmt.Errorf("failed to load state data with id=%s : %w", e.Msg.ParentThreadID(), err)
	}

	req, found := s.getNextRequestFunc(state)
	if !found {
		return errIgnoredDidEvent
	}

	bytes, err := s.extractDIDCommMsgBytesFunc(req)
	if err != nil {
		return fmt.Errorf("failed to extract didcomm message from attachment : %w", err)
	}

	record, err := s.fetchConnectionRecord(state.ConnectionID)
	if err != nil {
		return fmt.Errorf("failed to fetch connection record with id=%s : %w", state.ConnectionID, err)
	}

	err = s.dispatch(bytes, record.MyDID, record.TheirDID)
	if err != nil {
		return fmt.Errorf("failed to dispatch message : %w", err)
	}

	// TODO do we need the capability to register for events from whatever protocol service is handling that msg?

	// TODO we're only processing a single message for now
	state.Done = true

	err = s.save(state)
	if err != nil {
		return fmt.Errorf("failed to update state : %w", err)
	}

	return nil
}

func (s *Service) save(state *myState) error {
	bytes, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to save state=%+v : %w", state, err)
	}

	err = s.store.Put(state.ID, bytes)
	if err != nil {
		return fmt.Errorf("failed to save state : %w", err)
	}

	return nil
}

func (s *Service) fetchMyState(id string) (*myState, error) {
	bytes, err := s.store.Get(id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch state data with id=%s : %w", id, err)
	}

	state := &myState{}

	err = json.Unmarshal(bytes, state)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal state %+v : %w", state, err)
	}

	return state, nil
}

func (s *Service) fetchConnectionRecord(id string) (*connection.Record, error) {
	r, err := s.connections.GetConnectionRecord(id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch connection record for id=%s : %w", id, err)
	}

	return r, nil
}

// TODO a request message contains an array of attachments (each a request in of itself).
//  Should we process in parallel? Would need a spec update.
func getNextRequest(state *myState) (*decorator.Attachment, bool) {
	if !state.Done {
		return state.Request.Requests[0], true
	}

	return nil, false
}

func extractDIDCommMsgBytes(_ *decorator.Attachment) ([]byte, error) {
	// TODO implement
	return nil, nil
}
