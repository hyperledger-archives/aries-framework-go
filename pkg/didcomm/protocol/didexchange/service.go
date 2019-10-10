/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/did"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/common/metadata"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

var logger = log.New("aries-framework/did-exchange/service")

// didCommChMessage type to correlate actionEvent message(go channel) with callback message(internal go channel).
type didCommChMessage struct {
	ID  string
	Err error
}

const (
	// DIDExchange did exchange protocol
	DIDExchange = "didexchange"
	// DIDExchangeSpec defines the did-exchange spec
	DIDExchangeSpec = metadata.AriesCommunityDID + ";spec/didexchange/1.0/"
	// ConnectionInvite defines the did-exchange invite message type.
	ConnectionInvite = DIDExchangeSpec + "invitation"
	// ConnectionRequest defines the did-exchange request message type.
	ConnectionRequest = DIDExchangeSpec + "request"
	// ConnectionResponse defines the did-exchange response message type.
	ConnectionResponse = DIDExchangeSpec + "response"
	// ConnectionAck defines the did-exchange ack message type.
	ConnectionAck = DIDExchangeSpec + "ack"
	// DIDExchangeServiceType is the service type to be used in DID document
	DIDExchangeServiceType = "did-communication"
	// ConnectionID connection id is created to retriever connection record from db
	ConnectionID = "connectionID"
	// InvitationID invitation id is created in invitation request
	InvitationID = "invitationID"
)

// message type to store data for eventing. This is retrieved during callback.
type message struct {
	Msg           *service.DIDCommMsg
	ThreadID      string
	NextStateName string
}

// provider contains dependencies for the DID exchange protocol and is typically created by using aries.Context()
type provider interface {
	OutboundDispatcher() dispatcher.Outbound
	StorageProvider() storage.Provider
}

type connectionStore interface {
	GetConnection(connectionID string) (*ConnectionRecord, error)
}

// Service for DID exchange protocol
type Service struct {
	service.Action
	service.Message
	ctx             context
	store           storage.Store
	callbackChannel chan didCommChMessage
	connectionStore connectionStore
}

type context struct {
	outboundDispatcher dispatcher.Outbound
	didCreator         did.Creator
}

// New return didexchange service
func New(didMaker did.Creator, prov provider) (*Service, error) {
	store, err := prov.StorageProvider().OpenStore(DIDExchange)
	if err != nil {
		return nil, err
	}

	svc := &Service{
		ctx: context{
			outboundDispatcher: prov.OutboundDispatcher(),
			didCreator:         didMaker},
		store: store,
		// TODO channel size - https://github.com/hyperledger/aries-framework-go/issues/246
		callbackChannel: make(chan didCommChMessage, 10),
		connectionStore: NewConnectionRecorder(store),
	}

	svc.startInternalListener()

	return svc, nil
}

// Handle didexchange msg
func (s *Service) Handle(msg *service.DIDCommMsg) error {
	// throw error if there is no action event registered for inbound messages
	aEvent := s.GetActionEvent()

	logger.Infof("entered into Handle exchange message : %s", msg.Payload)

	if !msg.Outbound && aEvent == nil {
		return errors.New("no clients are registered to handle the message")
	}

	thid, err := threadID(msg)
	if err != nil {
		return err
	}
	logger.Infof("thread id value for the did exchange msg : %s", thid)

	current, err := s.currentState(thid)
	if err != nil {
		return err
	}
	logger.Infof("current state : %s", current.Name())

	next, err := stateFromMsgType(msg.Type)
	if err != nil {
		return err
	}
	logger.Infof("state will transition to -> %s if the msgType is processed", next.Name())

	if !current.CanTransitionTo(next) {
		return fmt.Errorf("invalid state transition: %s -> %s", current.Name(), next.Name())
	}

	// trigger message events
	// TODO change from thread id to connection id #397
	// TODO pass invitation id #397
	s.sendMsgEvents(&service.StateMsg{
		Type: service.PreState, Msg: msg, StateID: next.Name(), Properties: s.createEventProperties(thid, "")})
	logger.Infof("sent pre event for state %s", next.Name())

	// trigger action event based on message type for inbound messages
	if !msg.Outbound && canTriggerActionEvents(msg.Type) {
		err = s.sendActionEvent(msg, aEvent, thid, next)
		if err != nil {
			return fmt.Errorf("send events failed: %w", err)
		}
		return nil
	}
	// if no action event is triggered, continue the execution
	return s.handle(&message{Msg: msg, ThreadID: thid, NextStateName: next.Name()})
}

// Name return service name
func (s *Service) Name() string {
	return DIDExchange
}

// Accept msg checks the msg type
func (s *Service) Accept(msgType string) bool {
	return msgType == ConnectionInvite ||
		msgType == ConnectionRequest ||
		msgType == ConnectionResponse ||
		msgType == ConnectionAck
}

func (s *Service) handle(msg *message) error {
	logger.Infof("entered into private handle didcomm message: %s ", msg)

	next, err := stateFromName(msg.NextStateName)
	if err != nil {
		return fmt.Errorf("invalid state name: %w", err)
	}
	logger.Infof("next valid state to transition -> %s ", next.Name())

	for !isNoOp(next) {
		// TODO change from thread id to connection id #397
		// TODO pass invitation id #397
		s.sendMsgEvents(&service.StateMsg{
			Type: service.PreState, Msg: msg.Msg, StateID: next.Name(),
			Properties: s.createEventProperties(msg.ThreadID, "")})
		logger.Infof("sent pre event for state %s", next.Name())

		var action stateAction
		var followup state

		followup, action, err = next.Execute(msg.Msg, msg.ThreadID, s.ctx)
		if err != nil {
			return fmt.Errorf("failed to execute state %s %w", next.Name(), err)
		}
		logger.Infof("finish execute next state: %s", next.Name())

		if err = s.update(msg.ThreadID, next); err != nil {
			return fmt.Errorf("failed to persist state %s %w", next.Name(), err)
		}
		logger.Infof("persisted the connection using %s and updated the state to %s",
			msg.ThreadID, next.Name())

		if err := action(); err != nil {
			return fmt.Errorf("failed to execute state action %s %w", next.Name(), err)
		}
		logger.Infof("finish execute state action: %s", next.Name())

		// TODO change from thread id to connection id #397
		// TODO pass invitation id #397
		s.sendMsgEvents(&service.StateMsg{
			Type: service.PostState, Msg: msg.Msg, StateID: next.Name(),
			Properties: s.createEventProperties(msg.ThreadID, "")})
		logger.Infof("sent post event for state %s", next.Name())

		next = followup
	}
	return nil
}

func (s *Service) createEventProperties(connectionID, invitationID string) *didExchangeEvent { //nolint: unparam
	return &didExchangeEvent{connectionID: connectionID, invitationID: invitationID}
}

// didExchangeEvent implements didexchange.Event interface.
type didExchangeEvent struct {
	connectionID string
	invitationID string
}

// ConnectionID returns DIDExchange connectionID.
func (ex *didExchangeEvent) ConnectionID() string {
	return ex.connectionID
}

// InvitationID returns DIDExchange invitationID.
func (ex *didExchangeEvent) InvitationID() string {
	return ex.invitationID
}

// sendEvent triggers the action event. This function stores the state of current processing and passes a callback
// function in the event message.
func (s *Service) sendActionEvent(msg *service.DIDCommMsg, aEvent chan<- service.DIDCommAction,
	threadID string, nextState state) error {
	jsonDoc, err := json.Marshal(&message{
		Msg:           msg,
		ThreadID:      threadID,
		NextStateName: nextState.Name(),
	})

	if err != nil {
		return fmt.Errorf("JSON marshalling of document failed: %w", err)
	}

	// save the incoming message in the store (to retrieve later when callback events are fired)
	id := generateRandomID()
	err = s.store.Put(id, jsonDoc)
	if err != nil {
		return fmt.Errorf("JSON marshalling of document failed: %w", err)
	}
	// create the message for the channel
	// TODO change from thread id to connection id #397
	// TODO pass invitation id #397
	didCommAction := service.DIDCommAction{
		ProtocolName: DIDExchange,
		Message:      msg,
		Continue: func() {
			s.processCallback(id, nil)
		},
		Stop: func(err error) {
			s.processCallback(id, err)
		},
		Properties: s.createEventProperties(threadID, ""),
	}

	// trigger the registered action event
	aEvent <- didCommAction

	return nil
}

// sendEvent triggers the message events.
func (s *Service) sendMsgEvents(msg *service.StateMsg) {
	msg.ProtocolName = DIDExchange

	// trigger the message events
	statusEvents := s.GetMsgEvents()

	for _, handler := range statusEvents {
		handler <- *msg
	}
}

// startInternalListener listens to messages in gochannel for callback messages from clients.
func (s *Service) startInternalListener() {
	go func() {
		for msg := range s.callbackChannel {
			// TODO handle error in callback - https://github.com/hyperledger/aries-framework-go/issues/242
			if err := s.process(msg); err != nil {
				// TODO handle error
				logger.Errorf(err.Error())
			}
		}
	}()
}

func (s *Service) processCallback(id string, err error) {
	// pass the callback data to internal channel. This is created to unblock consumer go routine and wrap the callback
	// channel internally.
	s.callbackChannel <- didCommChMessage{ID: id, Err: err}
}

// processCallback processes the callback events.
func (s *Service) process(msg didCommChMessage) error {
	if msg.Err != nil {
		// TODO https://github.com/hyperledger/aries-framework-go/issues/438 Cleanup/Update data on Stop Event Action
		logger.Errorf("client action event processing failed - msgID:%s error:%s", msg.ID, msg.Err)
		return nil
	}

	// fetch the record
	jsonDoc, err := s.store.Get(msg.ID)
	if err != nil {
		return fmt.Errorf("document for the id doesn't exists in the database: %w", err)
	}

	document := &message{}
	err = json.Unmarshal(jsonDoc, document)
	if err != nil {
		return fmt.Errorf("JSON marshalling failed: %w", err)
	}

	// continue the processing
	err = s.handle(document)
	if err != nil {
		return fmt.Errorf("processing of the message failed: %w", err)
	}
	return nil
}

func isNoOp(s state) bool {
	_, ok := s.(*noOp)
	return ok
}

func threadID(didCommMsg *service.DIDCommMsg) (string, error) {
	var thid string
	if !didCommMsg.Outbound && didCommMsg.Type == ConnectionInvite {
		return uuid.New().String(), nil
	}
	msg := struct {
		ID     string           `json:"@id"`
		Thread decorator.Thread `json:"~thread,omitempty"`
	}{}
	err := json.Unmarshal(didCommMsg.Payload, &msg)
	if err != nil {
		return "", fmt.Errorf("cannot unmarshal @id and ~thread: error=%s", err)
	}
	thid = msg.ID
	if len(msg.Thread.ID) > 0 {
		thid = msg.Thread.ID
	}
	return thid, nil
}

func (s *Service) currentState(thid string) (state, error) {
	conn, err := s.connectionStore.GetConnection(thid)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return &null{}, nil
		}
		return nil, fmt.Errorf("cannot fetch state from store: thid=%s err=%s", thid, err)
	}
	return stateFromName(conn.State)
}

func (s *Service) update(thid string, state state) error {
	err := s.store.Put(thid, []byte(state.Name()))
	if err != nil {
		return fmt.Errorf("failed to write to store: %s", err)
	}
	return nil
}

func generateRandomID() string {
	return uuid.New().String()
}

// canTriggerActionEvents checks if the incoming message type matches either ConnectionRequest, ConnectionResponse or
// ConnectionAck type.
func canTriggerActionEvents(msgType string) bool {
	if msgType != ConnectionRequest &&
		msgType != ConnectionResponse && msgType != ConnectionAck {
		return false
	}

	return true
}
