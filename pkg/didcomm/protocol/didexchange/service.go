/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/did"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/common/metadata"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

var logger = log.New("aries-framework/did-exchange/service")

// didCommChMessage type to correlate actionEvent message(go channel) with callback message(internal go channel).
type didCommChMessage struct {
	ID              string
	DIDCommCallback dispatcher.DIDCommCallback
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
)

// message type to store data for eventing. This is retrieved during callback.
type message struct {
	Msg           dispatcher.DIDCommMsg
	ThreadID      string
	NextStateName string
}

// provider contains dependencies for the DID exchange protocol and is typically created by using aries.Context()
type provider interface {
	OutboundDispatcher() dispatcher.Outbound
}

// Service for DID exchange protocol
type Service struct {
	ctx             context
	store           storage.Store
	callbackChannel chan didCommChMessage
	actionEvent     chan<- dispatcher.DIDCommAction
	msgEvents       []chan<- dispatcher.StateMsg
	lock            sync.RWMutex
	msgEventLock    sync.RWMutex
}

type context struct {
	outboundDispatcher dispatcher.Outbound
	didCreator         did.Creator
}

// New return didexchange service
func New(store storage.Store, didMaker did.Creator, prov provider) *Service {
	svc := &Service{
		ctx: context{
			outboundDispatcher: prov.OutboundDispatcher(),
			didCreator:         didMaker},
		store: store,
		// TODO channel size - https://github.com/hyperledger/aries-framework-go/issues/246
		callbackChannel: make(chan didCommChMessage, 10),
	}

	svc.startInternalListener()

	return svc
}

// Handle didexchange msg
func (s *Service) Handle(msg dispatcher.DIDCommMsg) error {
	// throw error if there is no action event registered for inbound messages
	s.lock.RLock()
	aEvent := s.actionEvent
	s.lock.RUnlock()

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
	logger.Infof("send pre event for state %s", next.Name())
	s.sendMsgEvents(&dispatcher.StateMsg{Type: dispatcher.PreState, Msg: msg, StateID: next.Name()})

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

// RegisterActionEvent on DID Exchange protocol messages. The events are triggered for incoming message types based on
// canTriggerActionEvents() function. The consumer need to invoke the callback to resume processing.
// Only one channel can be registered for the action events. The function will throw error if a channel is already
// registered. The AutoExecuteActionEvent() function can be used to automatically trigger callback function for the
// event.
func (s *Service) RegisterActionEvent(ch chan<- dispatcher.DIDCommAction) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.actionEvent != nil {
		return errors.New("channel is already registered for the action event")
	}

	s.actionEvent = ch
	return nil
}

// UnregisterActionEvent on DID Exchange protocol messages. Refer RegisterActionEvent().
func (s *Service) UnregisterActionEvent(ch chan<- dispatcher.DIDCommAction) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.actionEvent != ch {
		return errors.New("invalid channel passed to unregister the action event")
	}

	s.actionEvent = nil

	return nil
}

// RegisterMsgEvent on DID Exchange protocol messages. The message events are triggered for incoming messages. Service
// will not expect any callback on these events unlike Action events.
func (s *Service) RegisterMsgEvent(ch chan<- dispatcher.StateMsg) error {
	s.msgEventLock.Lock()
	s.msgEvents = append(s.msgEvents, ch)
	s.msgEventLock.Unlock()

	return nil
}

// UnregisterMsgEvent on DID Exchange protocol messages. Refer RegisterMsgEvent().
func (s *Service) UnregisterMsgEvent(ch chan<- dispatcher.StateMsg) error {
	s.msgEventLock.Lock()
	for i := 0; i < len(s.msgEvents); i++ {
		if s.msgEvents[i] == ch {
			s.msgEvents = append(s.msgEvents[:i], s.msgEvents[i+1:]...)
			i--
		}
	}
	s.msgEventLock.Unlock()

	return nil
}

func (s *Service) handle(msg *message) error {
	logger.Infof("entered into private handle didcomm message: %s ", msg)

	next, err := stateFromName(msg.NextStateName)
	if err != nil {
		return fmt.Errorf("invalid state name: %w", err)
	}

	logger.Infof("next valid state to transition -> %s ", next.Name())

	followup, action, err := next.Execute(msg.Msg, msg.ThreadID, s.ctx)
	if err != nil {
		return fmt.Errorf("failed to execute state %s %w", next.Name(), err)
	}
	logger.Infof("follow up state that need to be executed immediately -> %s", followup.Name())

	err = s.update(msg.ThreadID, next)
	if err != nil {
		return fmt.Errorf("failed to persist state %s %w", next.Name(), err)
	}
	logger.Infof("persisted the connection using %s and updating the state to %s", msg.ThreadID, followup.Name())

	err = action()
	if err != nil {
		return fmt.Errorf("failed to execute state action %s %w", followup.Name(), err)
	}
	logger.Infof("finish execute state action: %s", followup.Name())

	logger.Infof("send post event for state %s", next.Name())
	s.sendMsgEvents(&dispatcher.StateMsg{Type: dispatcher.PostState, Msg: msg.Msg, StateID: next.Name()})

	for ; !isNoOp(followup); followup = next {
		logger.Infof("send pre event for state %s", followup.Name())
		s.sendMsgEvents(&dispatcher.StateMsg{Type: dispatcher.PreState, Msg: msg.Msg, StateID: followup.Name()})
		logger.Infof("execute next state: %s", followup.Name())
		var action stateAction
		next, action, err = followup.Execute(msg.Msg, msg.ThreadID, s.ctx)
		if err != nil {
			return fmt.Errorf("failed to execute state %s %w", followup.Name(), err)
		}
		logger.Infof("finish execute next state: %s", followup.Name())
		err = s.update(msg.ThreadID, followup)
		if err != nil {
			return fmt.Errorf("failed to persist state %s %w", followup.Name(), err)
		}
		logger.Infof("persisted the connection using %s and updating the state to %s", msg.ThreadID, followup.Name())
		err = action()
		if err != nil {
			return fmt.Errorf("failed to execute state action %s %w", followup.Name(), err)
		}
		logger.Infof("finish execute state action: %s", followup.Name())

		logger.Infof("send post event for state %s", followup.Name())
		s.sendMsgEvents(&dispatcher.StateMsg{Type: dispatcher.PostState, Msg: msg.Msg, StateID: followup.Name()})
	}
	logger.Infof("--exited internal handle function--")
	return nil
}

// sendEvent triggers the action event. This function stores the state of current processing and passes a callback
// function in the event message.
func (s *Service) sendActionEvent(msg dispatcher.DIDCommMsg, aEvent chan<- dispatcher.DIDCommAction,
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
	didCommAction := dispatcher.DIDCommAction{
		Message: msg,
		Callback: func(didCommCallback dispatcher.DIDCommCallback) {
			s.processCallback(id, didCommCallback)
		},
	}

	// trigger the registered action event
	aEvent <- didCommAction

	return nil
}

// sendEvent triggers the message events.
func (s *Service) sendMsgEvents(msg *dispatcher.StateMsg) {
	// trigger the message events
	s.msgEventLock.RLock()
	statusEvents := s.msgEvents
	s.msgEventLock.RUnlock()

	for _, handler := range statusEvents {
		handler <- *msg
	}
}

// startInternalListener listens to messages in gochannel for callback messages from clients.
func (s *Service) startInternalListener() {
	go func() {
		for msg := range s.callbackChannel {
			// TODO handle error in callback - https://github.com/hyperledger/aries-framework-go/issues/242
			if err := s.process(msg.ID, msg.DIDCommCallback); err != nil {
				// TODO handle error
				logger.Errorf(err.Error())
			}
		}
	}()
}

func (s *Service) processCallback(id string, didCommCallback dispatcher.DIDCommCallback) {
	// pass the callback data to internal channel. This is created to unblock consumer go routine and wrap the callback
	// channel internally.
	s.callbackChannel <- didCommChMessage{ID: id, DIDCommCallback: didCommCallback}
}

// processCallback processes the callback events.
func (s *Service) process(id string, didCommCallback dispatcher.DIDCommCallback) error {
	if didCommCallback.Err != nil {
		// TODO https://github.com/hyperledger/aries-framework-go/issues/242 Service callback processing error handling
		return nil
	}

	// fetch the record
	jsonDoc, err := s.store.Get(id)
	if err != nil {
		return fmt.Errorf("document for the id doesn't exists in the database: %w", didCommCallback.Err)
	}

	document := &message{}
	err = json.Unmarshal(jsonDoc, document)
	if err != nil {
		return fmt.Errorf("JSON marshalling failed: %w", didCommCallback.Err)
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

func threadID(didCommMsg dispatcher.DIDCommMsg) (string, error) {
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
	name, err := s.store.Get(thid)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return &null{}, nil
		}
		return nil, fmt.Errorf("cannot fetch state from store: thid=%s err=%s", thid, err)
	}
	return stateFromName(string(name))
}

func (s *Service) update(thid string, state state) error {
	err := s.store.Put(thid, []byte(state.Name()))
	if err != nil {
		return fmt.Errorf("failed to write to store: %s", err)
	}
	return nil
}

// Accept msg checks the msg type
func (s *Service) Accept(msgType string) bool {
	return msgType == ConnectionInvite ||
		msgType == ConnectionRequest ||
		msgType == ConnectionResponse ||
		msgType == ConnectionAck
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
func generateRandomID() string {
	return uuid.New().String()
}

func encodedExchangeInvitation(inviteMessage *Invitation) (string, error) {
	inviteMessage.Type = ConnectionInvite

	invitationJSON, err := json.Marshal(inviteMessage)
	if err != nil {
		return "", fmt.Errorf("JSON Marshal Error : %w", err)
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

// AutoExecuteActionEvent is a utility function to execute events automatically. The function requires a channel to be
// passed-in to listen for dispatcher.DIDCommAction and triggers the callback. This is a blocking function and use
// this function with a goroutine.
//
// Usage:
//  s := didexchange.New(....)
//	actionCh := make(chan dispatcher.DIDCommAction)
//	err = s.RegisterActionEvent(actionCh)
//	go didexchange.AutoExecuteActionEvent(actionCh)
func AutoExecuteActionEvent(ch chan dispatcher.DIDCommAction) error {
	for msg := range ch {
		msg.Callback(dispatcher.DIDCommCallback{Err: nil})
	}

	return nil
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
