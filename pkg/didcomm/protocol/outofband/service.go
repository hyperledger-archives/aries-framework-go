/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

const (
	// Name of this protocol service.
	Name = "out-of-band"
	// RequestMsgType is the '@type' for the request message.
	RequestMsgType = "https://didcomm.org/oob-request/1.0/request"
	// InvitationMsgType is the '@type' for the invitation message.
	InvitationMsgType = "https://didcomm.org/oob-invitation/1.0/invitation"

	// StateRequested is one of the possible states of this protocol.
	StateRequested = "requested"
	// StateInvited is this protocol's state after accepting an invitation
	StateInvited = "invited"

	// TODO channel size - https://github.com/hyperledger/aries-framework-go/issues/246
	callbackChannelSize = 10
)

var logger = log.New(fmt.Sprintf("aries-framework/%s/service", Name))

var errIgnoredDidEvent = errors.New("ignored")

type didExchSvc interface {
	RespondTo(*didexchange.OOBInvitation) (string, error)
	SaveInvitation(invitation *didexchange.OOBInvitation) error
}

// Service implements the Out-Of-Band protocol.
type Service struct {
	service.Action
	service.Message
	callbackChannel            chan *callback
	didSvc                     didExchSvc
	didEvents                  chan service.StateMsg
	store                      storage.Store
	connections                *connection.Recorder
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
	Invitation   *Invitation
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

	didSvc, ok := svc.(didExchSvc)
	if !ok {
		return nil, errors.New("failed to cast the didexchange service to satisfy our dependency")
	}

	store, err := p.TransientStorageProvider().OpenStore(Name)
	if err != nil {
		return nil, fmt.Errorf("failed to open the store : %w", err)
	}

	connectionRecorder, err := connection.NewRecorder(p)
	if err != nil {
		return nil, fmt.Errorf("failed to open a connection.Lookup : %w", err)
	}

	s := &Service{
		callbackChannel:            make(chan *callback, callbackChannelSize),
		didSvc:                     didSvc,
		didEvents:                  make(chan service.StateMsg, callbackChannelSize),
		store:                      store,
		connections:                connectionRecorder,
		dispatch:                   p.InboundMessageHandler(),
		getNextRequestFunc:         getNextRequest,
		extractDIDCommMsgBytesFunc: extractDIDCommMsgBytes,
	}

	s.listenerFunc = listener(s.callbackChannel, s.didEvents, s.handleCallback, s.handleDIDEvent, &s.Message)

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
	return msgType == RequestMsgType || msgType == InvitationMsgType
}

// HandleInbound handles inbound messages
func (s *Service) HandleInbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	logger.Debugf("receive inbound message : %s", msg)

	if !s.Accept(msg.Type()) {
		return "", fmt.Errorf("unsupported message type %s", msg.Type())
	}

	events := s.ActionEvent()
	if events == nil {
		return "", fmt.Errorf("no clients registered to handle action events for %s protocol", Name)
	}

	// TODO should request messages with no attachments be rejected?
	//  https://github.com/hyperledger/aries-rfcs/issues/451

	go func() {
		sendMsgEvent(service.PreState, &s.Message, msg, &eventProps{})

		event := service.DIDCommAction{
			ProtocolName: Name,
			Message:      msg,
			Continue:     continueFunc(s.callbackChannel, msg, myDID, theirDID),
			Stop: func(e error) {
				// TODO noop - nothing to do here (not even cleanup)
			},
			Properties: &eventProps{},
		}

		events <- event

		logger.Debugf("dispatched event: %+v", event)
	}()

	return "", nil
}

func sendMsgEvent(t service.StateMsgType, listeners *service.Message, msg service.DIDCommMsg, p *eventProps) {
	var stateName string

	if msg.Type() == RequestMsgType {
		stateName = StateRequested
	} else {
		stateName = StateInvited
	}

	stateMsg := service.StateMsg{
		ProtocolName: Name,
		Type:         t,
		StateID:      stateName,
		Msg:          msg,
		Properties:   p,
	}

	logger.Debugf("sending state msg: %+v\n", stateMsg)

	for _, handler := range listeners.MsgEvents() {
		handler <- stateMsg
	}
}

// HandleOutbound handles outbound messages
func (s *Service) HandleOutbound(_ service.DIDCommMsg, _, _ string) error {
	// TODO implement
	return errors.New("not implemented")
}

// AcceptRequest from another agent and return the connection ID.
func (s *Service) AcceptRequest(r *Request) (string, error) {
	connID, err := s.handleCallback(&callback{
		msg: service.NewDIDCommMsgMap(r),
	})
	if err != nil {
		return "", fmt.Errorf("failed to accept request : %w", err)
	}

	return connID, err
}

// AcceptInvitation from another agent and return the connection ID.
func (s *Service) AcceptInvitation(i *Invitation) (string, error) {
	connID, err := s.handleCallback(&callback{
		msg: service.NewDIDCommMsgMap(i),
	})

	if err != nil {
		return "", fmt.Errorf("failed to accept invitation : %w", err)
	}

	return connID, nil
}

// SaveRequest created by the outofband client.
func (s *Service) SaveRequest(r *Request) error {
	// TODO where should we save this request? - https://github.com/hyperledger/aries-framework-go/issues/1547
	err := s.connections.SaveInvitation(r.ID+"-TODO", r)
	if err != nil {
		return fmt.Errorf("failed to save oob request : %w", err)
	}

	target, err := chooseTarget(r.Service)
	if err != nil {
		return fmt.Errorf("failed to choose a target to perform did-exchange against : %w", err)
	}

	err = s.didSvc.SaveInvitation(&didexchange.OOBInvitation{
		ID:       uuid.New().String(),
		ThreadID: r.ID,
		Label:    r.Label,
		Target:   target,
	})
	if err != nil {
		return fmt.Errorf("the didexchange service failed to save the oob invitation : %w", err)
	}

	return nil
}

// SaveInvitation created by the outofband client.
func (s *Service) SaveInvitation(i *Invitation) error {
	target, err := chooseTarget(i.Service)
	if err != nil {
		return fmt.Errorf("failed to choose a target to connect against : %w", err)
	}

	// TODO where should we save this invitation? - https://github.com/hyperledger/aries-framework-go/issues/1547
	err = s.connections.SaveInvitation(i.ID+"-TODO", i)
	if err != nil {
		return fmt.Errorf("failed to save oob invitation : %w", err)
	}

	err = s.didSvc.SaveInvitation(&didexchange.OOBInvitation{
		ID:       uuid.New().String(),
		ThreadID: i.ID,
		Label:    i.Label,
		Target:   target,
	})
	if err != nil {
		return fmt.Errorf("the didexchange service failed to save the oob invitation : %w", err)
	}

	return nil
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
	handleCallbackFunc func(*callback) (string, error),
	handleDidEventFunc func(msg service.StateMsg) error,
	msgHandlers *service.Message) func() {
	return func() {
		for {
			select {
			case c := <-callbacks:
				switch c.msg.Type() {
				case RequestMsgType, InvitationMsgType:
					connID, err := handleCallbackFunc(c)
					if err != nil {
						logutil.LogError(logger, Name, "handleCallback", err.Error(),
							logutil.CreateKeyValueString("msgType", c.msg.Type()),
							logutil.CreateKeyValueString("msgID", c.msg.ID()))

						go sendMsgEvent(service.PostState, msgHandlers, c.msg, &eventProps{err: err})

						continue
					}

					go sendMsgEvent(service.PostState, msgHandlers, c.msg, &eventProps{connID: connID})
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

func (s *Service) handleCallback(c *callback) (string, error) {
	switch c.msg.Type() {
	case RequestMsgType:
		return s.handleRequestCallback(c)
	case InvitationMsgType:
		return s.handleInvitationCallback(c)
	default:
		return "", fmt.Errorf("unsupported message type: %s", c.msg.Type())
	}
}

func (s *Service) handleRequestCallback(c *callback) (string, error) {
	// TODO refactor didexchange.Service to accept an object other than didexchange.Invitation
	//  https://github.com/hyperledger/aries-framework-go/issues/1501
	invitation, req, err := decodeInvitationAndRequest(c.msg)
	if err != nil {
		return "", fmt.Errorf("failed to decode didexchange invitation and out-of-band request : %w", err)
	}

	connID, err := s.didSvc.RespondTo(invitation)
	if err != nil {
		return "", fmt.Errorf("didexchange service failed to handle inbound request : %w", err)
	}

	// TODO if we want to implement retries then we should be saving state before invoking
	//  the didexchange service

	err = s.save(&myState{
		// the pthid of the didexchange thread will equal this invitation's ID as per the RFC
		ID:           invitation.ID,
		ConnectionID: connID,
		Request:      req,
	})
	if err != nil {
		return "", fmt.Errorf("failed to save my state : %w", err)
	}

	return connID, nil
}

func (s *Service) handleInvitationCallback(c *callback) (string, error) {
	didInv, oobInv, err := decodeDIDInvitationAndOOBInvitation(c.msg)
	if err != nil {
		return "", fmt.Errorf("handleInvitationCallback: failed to decode callback message : %w", err)
	}

	connID, err := s.didSvc.RespondTo(didInv)
	if err != nil {
		return "", fmt.Errorf("didexchange service failed to handle inbound invitation : %w", err)
	}

	state := &myState{
		ID:           didInv.ID,
		ConnectionID: connID,
		Invitation:   oobInv,
	}

	err = s.save(state)
	if err != nil {
		return "", fmt.Errorf("failed to save my state : %w", err)
	}

	return connID, nil
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

func decodeInvitationAndRequest(msg service.DIDCommMsg) (*didexchange.OOBInvitation, *Request, error) {
	req := &Request{}

	err := msg.Decode(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode out-of-band request message : %w", err)
	}

	invitation := &didexchange.OOBInvitation{
		ID:       uuid.New().String(),
		ThreadID: req.ID,
		Label:    req.Label,
	}

	target, err := chooseTarget(req.Service)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to choose a target to perform did-exchange against : %w", err)
	}

	invitation.Target = target

	// TODO support explicit invitations : https://github.com/hyperledger/aries-framework-go/issues/1502
	return invitation, req, nil
}

func decodeDIDInvitationAndOOBInvitation(msg service.DIDCommMsg) (*didexchange.OOBInvitation, *Invitation, error) {
	oobInv := &Invitation{}

	err := msg.Decode(oobInv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode out-of-band invitation mesesage : %w", err)
	}

	target, err := chooseTarget(oobInv.Service)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to choose a target to connect against : %w", err)
	}

	didInv := &didexchange.OOBInvitation{
		ID:       uuid.New().String(),
		ThreadID: oobInv.ID,
		Label:    oobInv.Label,
		Target:   target,
	}

	return didInv, oobInv, nil
}

func chooseTarget(svcs []interface{}) (interface{}, error) {
	for i := range svcs {
		switch svc := svcs[i].(type) {
		case string, *did.Service:
			return svc, nil
		case map[string]interface{}:
			var s did.Service

			decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{TagName: "json", Result: &s})
			if err != nil {
				return nil, fmt.Errorf("failed to initialize decoder : %w", err)
			}

			err = decoder.Decode(svc)
			if err != nil {
				return nil, fmt.Errorf("failed to decode service block : %w", err)
			}

			return &s, nil
		}
	}

	return nil, fmt.Errorf("invalid or no targets to choose from")
}

type eventProps struct {
	connID string
	err    error
}

func (e *eventProps) ConnectionID() string {
	return e.connID
}

func (e *eventProps) Error() error {
	return e.err
}
