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
	"github.com/hyperledger/aries-framework-go/pkg/framework/didresolver"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
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
	// InvitationMsgType defines the did-exchange invite message type.
	InvitationMsgType = DIDExchangeSpec + "invitation"
	// RequestMsgType defines the did-exchange request message type.
	RequestMsgType = DIDExchangeSpec + "request"
	// ResponseMsgType defines the did-exchange response message type.
	ResponseMsgType = DIDExchangeSpec + "response"
	// AckMsgType defines the did-exchange ack message type.
	AckMsgType = DIDExchangeSpec + "ack"
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
	Record        *ConnectionRecord
}

// provider contains dependencies for the DID exchange protocol and is typically created by using aries.Context()
type provider interface {
	OutboundDispatcher() dispatcher.Outbound
	StorageProvider() storage.Provider
	Signer() wallet.Signer
	DIDResolver() didresolver.Resolver
}

// stateMachineMsg is an internal struct used to pass data to state machine.
type stateMachineMsg struct {
	outbound            bool
	outboundDestination *service.Destination
	header              *service.Header
	payload             []byte
}

// Service for DID exchange protocol
type Service struct {
	service.Action
	service.Message
	ctx             *context
	store           storage.Store
	callbackChannel chan didCommChMessage
	connectionStore *ConnectionRecorder
}

type context struct {
	outboundDispatcher dispatcher.Outbound
	didCreator         did.Creator
	signer             wallet.Signer
	didResolver        didresolver.Resolver
	connectionStore    *ConnectionRecorder
}

// New return didexchange service
func New(didMaker did.Creator, prov provider) (*Service, error) {
	store, err := prov.StorageProvider().OpenStore(DIDExchange)
	if err != nil {
		return nil, err
	}

	svc := &Service{
		ctx: &context{
			outboundDispatcher: prov.OutboundDispatcher(),
			didCreator:         didMaker,
			signer:             prov.Signer(),
			didResolver:        prov.DIDResolver(),
			connectionStore:    NewConnectionRecorder(store),
		},
		store: store,
		// TODO channel size - https://github.com/hyperledger/aries-framework-go/issues/246
		callbackChannel: make(chan didCommChMessage, 10),
		connectionStore: NewConnectionRecorder(store),
	}

	// start the listener
	go svc.startInternalListener()

	return svc, nil
}

// HandleInbound handles inbound didexchange messages.
func (s *Service) HandleInbound(msg *service.DIDCommMsg) error {
	// throw error if there is no action event registered for inbound messages
	aEvent := s.ActionEvent()

	logger.Infof("entered into HandleInbound exchange message : %s", msg.Payload)

	if aEvent == nil {
		return errors.New("no clients are registered to handle the message")
	}
	thid, err := threadID(msg)
	if err != nil {
		return err
	}
	logger.Infof("thread id value for the did exchange msg : %s", thid)

	nsThid, err := createNSKey(findNameSpace(msg.Header.Type), thid)
	if err != nil {
		return err
	}
	current, err := s.currentState(nsThid)
	if err != nil {
		return err
	}
	logger.Infof("current state : %s", current.Name())

	next, err := stateFromMsgType(msg.Header.Type)
	if err != nil {
		return err
	}
	logger.Infof("state will transition to -> %s if the msgType is processed", next.Name())

	if !current.CanTransitionTo(next) {
		return fmt.Errorf("invalid state transition: %s -> %s", current.Name(), next.Name())
	}
	// trigger action event based on message type for inbound messages
	if canTriggerActionEvents(msg.Header.Type) {
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

func findNameSpace(msgType string) string {
	namespace := theirNSPrefix
	if msgType == InvitationMsgType || msgType == ResponseMsgType {
		namespace = myNSPrefix
	}
	return namespace
}

// Accept msg checks the msg type
func (s *Service) Accept(msgType string) bool {
	return msgType == InvitationMsgType ||
		msgType == RequestMsgType ||
		msgType == ResponseMsgType ||
		msgType == AckMsgType
}

// HandleOutbound handles outbound didexchange messages.
func (s *Service) HandleOutbound(msg *service.DIDCommMsg, destination *service.Destination) error {
	// TODO https://github.com/hyperledger/aries-framework-go/issues/500 Support to initiate DIDExchange through exRequest
	return errors.New("not implemented")
}

func (s *Service) handle(msg *message) error {
	logger.Infof("entered into private handle didcomm message with threadID: %s ", msg.ThreadID)

	next, err := stateFromName(msg.NextStateName)
	if err != nil {
		return fmt.Errorf("invalid state name: %w", err)
	}
	logger.Infof("next valid state to transition -> %s ", next.Name())
	for !isNoOp(next) {
		//TODO: Issue-578 is created to consider if we need to create connection ID at pre state level or no
		s.sendMsgEvents(&service.StateMsg{
			Type: service.PreState, Msg: msg.Msg, StateID: next.Name(),
			Properties: createEventProperties("", "")})
		logger.Infof("sent pre event for state %s", next.Name())

		var action stateAction
		var followup state
		var connectionRecord *ConnectionRecord

		connectionRecord, followup, action, err = next.Execute(&stateMachineMsg{
			header: msg.Msg.Header, payload: msg.Msg.Payload}, msg.ThreadID, s.ctx)
		if err != nil {
			return fmt.Errorf("failed to execute state %s %w", next.Name(), err)
		}
		connectionRecord.State = next.Name()
		logger.Infof("finish execute next state: %s -> namespace -> %s", next.Name(), connectionRecord.Namespace)

		if err = s.update(msg.Msg.Header.Type, connectionRecord); err != nil {
			return fmt.Errorf("failed to persist state %s %w", next.Name(), err)
		}

		logger.Infof("persisted the connection using %s and updated the state to %s",
			connectionRecord.ThreadID, next.Name())

		if err := action(); err != nil {
			return fmt.Errorf("failed to execute state action %s %w", next.Name(), err)
		}
		logger.Infof("finish execute state action: %s", next.Name())
		s.sendMsgEvents(&service.StateMsg{
			Type: service.PostState, Msg: msg.Msg, StateID: next.Name(),
			Properties: createEventProperties(connectionRecord.ConnectionID, connectionRecord.InvitationID)})
		logger.Infof("sent post event for state %s", next.Name())

		next = followup
	}
	return nil
}

func createEventProperties(connectionID, invitationID string) *didExchangeEvent { //nolint: unparam
	return &didExchangeEvent{
		connectionID: connectionID,
		invitationID: invitationID,
	}
}

func createErrorEventProperties(connectionID, invitationID string, err error) *didExchangeEventError { //nolint: unparam
	return &didExchangeEventError{
		err:              err,
		didExchangeEvent: createEventProperties(connectionID, invitationID),
	}
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
	}

	// trigger the registered action event
	aEvent <- didCommAction
	return nil
}

// sendEvent triggers the message events.
func (s *Service) sendMsgEvents(msg *service.StateMsg) {
	msg.ProtocolName = DIDExchange
	// trigger the message events
	statusEvents := s.MsgEvents()

	for _, handler := range statusEvents {
		handler <- *msg
	}
}

// startInternalListener listens to messages in gochannel for callback messages from clients.
func (s *Service) startInternalListener() {
	for msg := range s.callbackChannel {
		if msg.Err != nil {
			// TODO https://github.com/hyperledger/aries-framework-go/issues/438 Cleanup/Update data on Stop Event Action
			logger.Errorf("client action event processing - msgID:%s error:%s", msg.ID, msg.Err)
			err := s.processFailure(msg.ID, msg.Err)
			if err != nil {
				logger.Errorf("process callback : %s", err)
			}
			continue
		}

		// TODO https://github.com/hyperledger/aries-framework-go/issues/242 - retry logic

		if err := s.process(msg.ID); err != nil {
			procErr := s.processFailure(msg.ID, err)
			if procErr != nil {
				logger.Errorf("process callback : %s", procErr)
			}
		}
	}
}

func (s *Service) processFailure(id string, processErr error) error {
	// get the transient data
	data, err := s.getTransientEventData(id)
	if err != nil {
		return fmt.Errorf("unable to fetch the event transient data: %w", err)
	}

	err = s.abandon(data.ThreadID, data.Msg, processErr)
	if err != nil {
		return fmt.Errorf("abandon : %w", err)
	}

	return nil
}

// abandon updates the state to abandoned and trigger failure event.
func (s *Service) abandon(thid string, msg *service.DIDCommMsg, processErr error) error {
	// update the state to abandoned
	nsThid, err := createNSKey(findNameSpace(msg.Header.Type), thid)
	if err != nil {
		return err
	}
	connRec, err := s.connectionStore.GetConnectionRecordByNSThreadID(nsThid)
	if err != nil {
		return fmt.Errorf("unable to update the state to abandoned: %w", err)
	}
	connRec.State = (&abandoned{}).Name()
	err = s.update(msg.Header.Type, connRec)
	if err != nil {
		return fmt.Errorf("unable to update the state to abandoned: %w", err)
	}

	// send the message event
	s.sendMsgEvents(&service.StateMsg{
		Type:       service.PostState,
		Msg:        msg,
		StateID:    stateNameAbandoned,
		Properties: createErrorEventProperties(thid, "", processErr),
	})

	return nil
}

func (s *Service) processCallback(id string, err error) {
	// pass the callback data to internal channel. This is created to unblock consumer go routine and wrap the callback
	// channel internally.
	s.callbackChannel <- didCommChMessage{ID: id, Err: err}
}

// process processes the callback events.
func (s *Service) process(id string) error {
	data, err := s.getTransientEventData(id)
	if err != nil {
		return fmt.Errorf("unable to fetch the event transient data: %w", err)
	}
	// continue the processing
	err = s.handle(data)
	if err != nil {
		return fmt.Errorf("processing of the message : %w", err)
	}
	return nil
}

// getTransientEventData fetches the transient event data.
func (s *Service) getTransientEventData(id string) (*message, error) {
	// fetch the record
	jsonDoc, err := s.store.Get(id)
	if err != nil {
		return nil, fmt.Errorf("document for the id doesn't exists in the database: %w", err)
	}
	data := &message{}
	err = json.Unmarshal(jsonDoc, data)
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling : %w", err)
	}
	return data, nil
}

func isNoOp(s state) bool {
	_, ok := s.(*noOp)
	return ok
}

func threadID(didCommMsg *service.DIDCommMsg) (string, error) {
	if didCommMsg.Header.Type == InvitationMsgType {
		return generateRandomID(), nil
	}

	return didCommMsg.ThreadID()
}

func (s *Service) currentState(nsThid string) (state, error) {
	connRec, err := s.connectionStore.GetConnectionRecordByNSThreadID(nsThid)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return &null{}, nil
		}
		return nil, fmt.Errorf("cannot fetch state from store: thid=%s err=%s", nsThid, err)
	}
	return stateFromName(connRec.State)
}

func (s *Service) update(msgType string, connectionRecord *ConnectionRecord) error {
	if (msgType == RequestMsgType && connectionRecord.State == stateNameRequested) ||
		(msgType == InvitationMsgType && connectionRecord.State == stateNameInvited) {
		return s.connectionStore.saveNewConnectionRecord(connectionRecord)
	}
	return s.connectionStore.saveConnectionRecord(connectionRecord)
}

func generateRandomID() string {
	return uuid.New().String()
}

// canTriggerActionEvents checks if the incoming message type matches either RequestMsgType type.
func canTriggerActionEvents(msgType string) bool {
	return msgType == RequestMsgType
}
