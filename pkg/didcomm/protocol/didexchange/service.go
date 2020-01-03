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

	"github.com/hyperledger/aries-framework-go/pkg/common/connectionstore"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/didconnection"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

var logger = log.New("aries-framework/did-exchange/service")

const (
	// DIDExchange did exchange protocol
	DIDExchange = "didexchange"
	// DIDExchangeSpec defines the did-exchange spec
	DIDExchangeSpec = "https://didcomm.org/didexchange/1.0/"
	// InvitationMsgType defines the did-exchange invite message type.
	InvitationMsgType = DIDExchangeSpec + "invitation"
	// RequestMsgType defines the did-exchange request message type.
	RequestMsgType = DIDExchangeSpec + "request"
	// ResponseMsgType defines the did-exchange response message type.
	ResponseMsgType = DIDExchangeSpec + "response"
	// AckMsgType defines the did-exchange ack message type.
	AckMsgType = DIDExchangeSpec + "ack"
)

// message type to store data for eventing. This is retrieved during callback.
type message struct {
	Msg           *service.DIDCommMsg
	ThreadID      string
	Options       *options
	NextStateName string
	ConnRecord    *connectionstore.ConnectionRecord
	// err is used to determine whether callback was stopped
	// e.g the user received an action event and executes Stop(err) function
	// in that case `err` is equal to `err` which was passing to Stop function
	err error
}

// provider contains dependencies for the DID exchange protocol and is typically created by using aries.Context()
type provider interface {
	OutboundDispatcher() dispatcher.Outbound
	StorageProvider() storage.Provider
	TransientStorageProvider() storage.Provider
	DIDConnectionStore() didconnection.Store
	Signer() kms.Signer
	VDRIRegistry() vdriapi.Registry
}

// stateMachineMsg is an internal struct used to pass data to state machine.
type stateMachineMsg struct {
	header     *service.Header
	payload    []byte
	connRecord *connectionstore.ConnectionRecord
	options    *options
}

// Service for DID exchange protocol
type Service struct {
	service.Action
	service.Message
	ctx             *context
	callbackChannel chan *message

	// TODO merge connection and did store [Issue #1004]
	didConnections  didconnection.Store
	connectionStore *connectionStore
}

type context struct {
	outboundDispatcher dispatcher.Outbound
	signer             kms.Signer
	connectionStore    *connectionStore
	vdriRegistry       vdriapi.Registry
}

// opts are used to provide client properties to DID Exchange service
type opts interface {
	// PublicDID allows for setting public DID
	PublicDID() string

	// Label allows for setting label
	Label() string
}

// New return didexchange service
func New(prov provider) (*Service, error) {
	connRecorder, err := newConnectionStore(prov)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize connection store : %w", err)
	}

	svc := &Service{
		ctx: &context{
			outboundDispatcher: prov.OutboundDispatcher(),
			signer:             prov.Signer(),
			vdriRegistry:       prov.VDRIRegistry(),
			connectionStore:    connRecorder,
		},
		// TODO channel size - https://github.com/hyperledger/aries-framework-go/issues/246
		callbackChannel: make(chan *message, 10),
		connectionStore: connRecorder,
		didConnections:  prov.DIDConnectionStore(),
	}

	// start the listener
	go svc.startInternalListener()

	return svc, nil
}

// HandleInbound handles inbound didexchange messages.
func (s *Service) HandleInbound(msg *service.DIDCommMsg, myDID, theirDID string) (string, error) {
	logger.Debugf("receive inbound message : %s", msg.Payload)

	// fetch the thread id
	thID, err := threadID(msg)
	if err != nil {
		return "", err
	}

	// valid state transition and get the next state
	next, err := s.nextState(msg.Header.Type, thID)
	if err != nil {
		return "", fmt.Errorf("handle inbound - next state : %w", err)
	}

	// connection record
	connRecord, err := s.connectionRecord(msg)
	if err != nil {
		return "", err
	}

	internalMsg := &message{Msg: msg, ThreadID: thID, NextStateName: next.Name(), ConnRecord: connRecord}

	go func(msg *message, aEvent chan<- service.DIDCommAction) {
		if err = s.handle(msg, aEvent); err != nil {
			logger.Errorf("didexchange processing error : %s", err)
		}
	}(internalMsg, s.ActionEvent())

	return connRecord.ConnectionID, nil
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
func (s *Service) HandleOutbound(msg *service.DIDCommMsg, myDID, theirDID string) error {
	return errors.New("not implemented")
}

func (s *Service) nextState(msgType, thID string) (state, error) {
	nsThID, err := createNSKey(findNameSpace(msgType), thID)
	if err != nil {
		return nil, err
	}

	current, err := s.currentState(nsThID)
	if err != nil {
		return nil, err
	}

	logger.Debugf("retrieved current state [%s] using nsThID [%s]", current.Name(), nsThID)

	next, err := stateFromMsgType(msgType)
	if err != nil {
		return nil, err
	}

	logger.Debugf("check if current state [%s] can transition to [%s]", current.Name(), next.Name())

	if !current.CanTransitionTo(next) {
		return nil, fmt.Errorf("invalid state transition: %s -> %s", current.Name(), next.Name())
	}

	return next, nil
}

func (s *Service) handle(msg *message, aEvent chan<- service.DIDCommAction) error { //nolint funlen
	next, err := stateFromName(msg.NextStateName)
	if err != nil {
		return fmt.Errorf("invalid state name: %w", err)
	}

	for !isNoOp(next) {
		s.sendMsgEvents(&service.StateMsg{
			ProtocolName: DIDExchange,
			Type:         service.PreState,
			Msg:          msg.Msg.Clone(),
			StateID:      next.Name(),
			Properties:   createEventProperties(msg.ConnRecord.ConnectionID, msg.ConnRecord.InvitationID),
		})
		logger.Debugf("sent pre event for state %s", next.Name())

		var (
			action           stateAction
			followup         state
			connectionRecord *connectionstore.ConnectionRecord
		)

		connectionRecord, followup, action, err = next.ExecuteInbound(
			&stateMachineMsg{
				header:     msg.Msg.Header,
				payload:    msg.Msg.Payload,
				connRecord: msg.ConnRecord,
				options:    msg.Options,
			},
			msg.ThreadID,
			s.ctx)

		if err != nil {
			return fmt.Errorf("failed to execute state %s %w", next.Name(), err)
		}

		connectionRecord.State = next.Name()
		logger.Debugf("finished execute state: %s", next.Name())

		if err = s.update(msg.Msg.Header.Type, connectionRecord); err != nil {
			return fmt.Errorf("failed to persist state %s %w", next.Name(), err)
		}

		logger.Debugf("persisted the connection record using connection id %s", connectionRecord.ConnectionID)

		if err = action(); err != nil {
			return fmt.Errorf("failed to execute state action %s %w", next.Name(), err)
		}

		logger.Debugf("finish execute state action: %s", next.Name())

		prev := next
		next = followup
		haltExecution := false

		// trigger action event based on message type for inbound messages
		if canTriggerActionEvents(connectionRecord.State, connectionRecord.Namespace) {
			msg.NextStateName = next.Name()
			if err = s.sendActionEvent(msg, aEvent); err != nil {
				return fmt.Errorf("handle inbound: %w", err)
			}

			haltExecution = true
		}

		s.sendMsgEvents(&service.StateMsg{
			ProtocolName: DIDExchange,
			Type:         service.PostState,
			Msg:          msg.Msg.Clone(),
			StateID:      prev.Name(),
			Properties:   createEventProperties(connectionRecord.ConnectionID, connectionRecord.InvitationID),
		})
		logger.Debugf("sent post event for state %s", prev.Name())

		if haltExecution {
			break
		}
	}

	return nil
}

func (s *Service) handleWithoutAction(msg *message) error {
	return s.handle(msg, nil)
}

func createEventProperties(connectionID, invitationID string) *didExchangeEvent {
	return &didExchangeEvent{
		connectionID: connectionID,
		invitationID: invitationID,
	}
}

func createErrorEventProperties(connectionID, invitationID string, err error) *didExchangeEventError {
	return &didExchangeEventError{
		err:              err,
		didExchangeEvent: createEventProperties(connectionID, invitationID),
	}
}

// sendActionEvent triggers the action event. This function stores the state of current processing and passes a callback
// function in the event message.
func (s *Service) sendActionEvent(internalMsg *message, aEvent chan<- service.DIDCommAction) error {
	// save data to support AcceptExchangeRequest APIs (when client will not be able to invoke the callback function)
	err := s.storeEventTransientData(internalMsg)
	if err != nil {
		return fmt.Errorf("send action event : %w", err)
	}

	if aEvent != nil {
		// trigger action event
		aEvent <- service.DIDCommAction{
			ProtocolName: DIDExchange,
			Message:      internalMsg.Msg.Clone(),
			Continue: func(args interface{}) {
				switch v := args.(type) {
				case opts:
					internalMsg.Options = &options{publicDID: v.PublicDID(), label: v.Label()}
				default:
					// nothing to do
				}

				s.processCallback(internalMsg)
			},
			Stop: func(err error) {
				// sets an error to the message
				internalMsg.err = err
				s.processCallback(internalMsg)
			},
			Properties: createEventProperties(internalMsg.ConnRecord.ConnectionID, internalMsg.ConnRecord.InvitationID),
		}
	}

	return nil
}

// sendEvent triggers the message events.
func (s *Service) sendMsgEvents(msg *service.StateMsg) {
	// trigger the message events
	for _, handler := range s.MsgEvents() {
		handler <- *msg
	}
}

// startInternalListener listens to messages in gochannel for callback messages from clients.
func (s *Service) startInternalListener() {
	for msg := range s.callbackChannel {
		// TODO https://github.com/hyperledger/aries-framework-go/issues/242 - retry logic
		// if no error - do handle
		if msg.err == nil {
			msg.err = s.handleWithoutAction(msg)
		}

		// no error - continue
		if msg.err == nil {
			continue
		}

		if err := s.abandon(msg.ThreadID, msg.Msg, msg.err); err != nil {
			logger.Errorf("process callback : %s", err)
		}
	}
}

// AcceptInvitation accepts/approves connection invitation.
func (s *Service) AcceptInvitation(connectionID, publicDID, label string) error {
	return s.accept(connectionID, publicDID, label, stateNameInvited, "accept exchange invitation")
}

// AcceptExchangeRequest accepts/approves connection request.
func (s *Service) AcceptExchangeRequest(connectionID, publicDID, label string) error {
	return s.accept(connectionID, publicDID, label, stateNameRequested, "accept exchange request")
}

func (s *Service) accept(connectionID, publicDID, label, stateID, errMsg string) error {
	msg, err := s.getEventTransientData(connectionID)
	if err != nil {
		return fmt.Errorf("%s : %w", errMsg, err)
	}

	connRecord, err := s.connectionStore.GetConnectionRecord(connectionID)
	if err != nil {
		return fmt.Errorf("%s : %w", errMsg, err)
	}

	if connRecord.State != stateID {
		return fmt.Errorf("current state (%s) is different from "+
			"expected state (%s)", connRecord.State, stateID)
	}

	msg.Options = &options{publicDID: publicDID, label: label}

	return s.handleWithoutAction(msg)
}

// SaveInvitation saves given invitation instance in connection store
func (s *Service) SaveInvitation(invitation *Invitation) error {
	return s.connectionStore.SaveInvitation(invitation)
}

func (s *Service) storeEventTransientData(msg *message) error {
	bytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("store transient data : %w", err)
	}

	return s.connectionStore.TransientStore().Put(eventTransientDataKey(msg.ConnRecord.ConnectionID), bytes)
}

func (s *Service) getEventTransientData(connectionID string) (*message, error) {
	val, err := s.connectionStore.TransientStore().Get(eventTransientDataKey(connectionID))
	if err != nil {
		return nil, fmt.Errorf("get transient data : %w", err)
	}

	msg := &message{}

	err = json.Unmarshal(val, msg)
	if err != nil {
		return nil, fmt.Errorf("get transient data : %w", err)
	}

	return msg, nil
}

func eventTransientDataKey(connectionID string) string {
	return "didex-event-" + connectionID
}

// abandon updates the state to abandoned and trigger failure event.
func (s *Service) abandon(thID string, msg *service.DIDCommMsg, processErr error) error {
	// update the state to abandoned
	nsThID, err := createNSKey(findNameSpace(msg.Header.Type), thID)
	if err != nil {
		return err
	}

	connRec, err := s.connectionStore.GetConnectionRecordByNSThreadID(nsThID)
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
		ProtocolName: DIDExchange,
		Type:         service.PostState,
		Msg:          msg.Clone(),
		StateID:      stateNameAbandoned,
		Properties:   createErrorEventProperties(thID, "", processErr),
	})

	return nil
}

func (s *Service) processCallback(msg *message) {
	// pass the callback data to internal channel. This is created to unblock consumer go routine and wrap the callback
	// channel internally.
	s.callbackChannel <- msg
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

func (s *Service) currentState(nsThID string) (state, error) {
	connRec, err := s.connectionStore.GetConnectionRecordByNSThreadID(nsThID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return &null{}, nil
		}

		return nil, fmt.Errorf("cannot fetch state from store: thID=%s err=%s", nsThID, err)
	}

	return stateFromName(connRec.State)
}

func (s *Service) update(msgType string, connectionRecord *connectionstore.ConnectionRecord) error {
	if (msgType == RequestMsgType && connectionRecord.State == stateNameRequested) ||
		(msgType == InvitationMsgType && connectionRecord.State == stateNameInvited) {
		return s.connectionStore.saveNewConnectionRecord(connectionRecord)
	}

	return s.connectionStore.saveConnectionRecord(connectionRecord)
}

func (s *Service) connectionRecord(msg *service.DIDCommMsg) (*connectionstore.ConnectionRecord, error) {
	switch msg.Header.Type {
	case InvitationMsgType:
		return s.invitationMsgRecord(msg)
	case RequestMsgType:
		return s.requestMsgRecord(msg)
	case ResponseMsgType:
		return s.responseMsgRecord(msg.Payload)
	case AckMsgType:
		return s.ackMsgRecord(msg.Payload)
	}

	return nil, errors.New("invalid message type")
}

func (s *Service) invitationMsgRecord(msg *service.DIDCommMsg) (*connectionstore.ConnectionRecord, error) {
	thID, msgErr := msg.ThreadID()
	if msgErr != nil {
		return nil, msgErr
	}

	invitation := &Invitation{}

	err := json.Unmarshal(msg.Payload, invitation)
	if err != nil {
		return nil, err
	}

	recKey, err := s.ctx.getInvitationRecipientKey(invitation)
	if err != nil {
		return nil, err
	}

	connRecord := &connectionstore.ConnectionRecord{
		ConnectionID:    generateRandomID(),
		ThreadID:        thID,
		State:           stateNameNull,
		InvitationID:    invitation.ID,
		InvitationDID:   invitation.DID,
		ServiceEndPoint: invitation.ServiceEndpoint,
		RecipientKeys:   []string{recKey},
		TheirLabel:      invitation.Label,
		Namespace:       findNameSpace(msg.Header.Type),
	}

	if err := s.connectionStore.saveConnectionRecord(connRecord); err != nil {
		return nil, err
	}

	return connRecord, nil
}

func (s *Service) requestMsgRecord(msg *service.DIDCommMsg) (*connectionstore.ConnectionRecord, error) {
	request := Request{}

	err := json.Unmarshal(msg.Payload, &request)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling failed: %s", err)
	}

	connRecord := &connectionstore.ConnectionRecord{
		ConnectionID: generateRandomID(),
		ThreadID:     request.ID,
		State:        stateNameNull,
		TheirDID:     request.Connection.DID,
		Namespace:    theirNSPrefix,
	}

	if err := s.connectionStore.saveConnectionRecord(connRecord); err != nil {
		return nil, err
	}

	return connRecord, nil
}

func (s *Service) responseMsgRecord(payload []byte) (*connectionstore.ConnectionRecord, error) {
	return s.fetchConnectionRecord(myNSPrefix, payload)
}

func (s *Service) ackMsgRecord(payload []byte) (*connectionstore.ConnectionRecord, error) {
	return s.fetchConnectionRecord(theirNSPrefix, payload)
}

func (s *Service) fetchConnectionRecord(nsPrefix string, payload []byte) (*connectionstore.ConnectionRecord, error) {
	msg := &struct {
		Thread decorator.Thread `json:"~thread,omitempty"`
	}{}

	err := json.Unmarshal(payload, msg)
	if err != nil {
		return nil, err
	}

	key, err := createNSKey(nsPrefix, msg.Thread.ID)
	if err != nil {
		return nil, err
	}

	return s.connectionStore.GetConnectionRecordByNSThreadID(key)
}

func generateRandomID() string {
	return uuid.New().String()
}

// canTriggerActionEvents true based on role and state.
// 1. Role is invitee and state is invited
// 2. Role is inviter and state is requested
func canTriggerActionEvents(stateID, ns string) bool {
	return (stateID == stateNameInvited && ns == myNSPrefix) || (stateID == stateNameRequested && ns == theirNSPrefix)
}

type options struct {
	publicDID string
	label     string
}

// CreateImplicitInvitation creates implicit invitation. Inviter DID is required, invitee DID is optional.
// If invitee DID is not provided new peer DID will be created for implicit invitation exchange request.
func (s *Service) CreateImplicitInvitation(inviterLabel, inviterDID, inviteeLabel, inviteeDID string) (string, error) {
	logger.Debugf("implicit invitation requested inviterDID[%s] inviteeDID[%s]", inviterDID, inviteeDID)

	didDoc, err := s.ctx.vdriRegistry.Resolve(inviterDID)
	if err != nil {
		return "", fmt.Errorf("resolve public did[%s]: %w", inviterDID, err)
	}

	dest, err := service.CreateDestination(didDoc)
	if err != nil {
		return "", err
	}

	thID := generateRandomID()
	connRecord := &connectionstore.ConnectionRecord{
		ConnectionID:    generateRandomID(),
		ThreadID:        thID,
		State:           stateNameNull,
		InvitationDID:   inviterDID,
		Implicit:        true,
		ServiceEndPoint: dest.ServiceEndpoint,
		RecipientKeys:   dest.RecipientKeys,
		TheirLabel:      inviterLabel,
		Namespace:       findNameSpace(InvitationMsgType),
	}

	if e := s.connectionStore.saveNewConnectionRecord(connRecord); e != nil {
		return "", fmt.Errorf("failed to save new connection record for implicit invitation: %w", e)
	}

	invitation := &Invitation{
		ID:    uuid.New().String(),
		Label: inviterLabel,
		DID:   inviterDID,
		Type:  InvitationMsgType}

	msg, err := createDIDCommMsg(invitation)
	if err != nil {
		return "", fmt.Errorf("failed to create DIDCommMsg for implicit invitation: %w", err)
	}

	next := &requested{}
	internalMsg := &message{Msg: msg, ThreadID: thID, NextStateName: next.Name(), ConnRecord: connRecord}
	internalMsg.Options = &options{publicDID: inviteeDID, label: inviteeLabel}

	go func(msg *message, aEvent chan<- service.DIDCommAction) {
		if err = s.handle(msg, aEvent); err != nil {
			logger.Errorf("error from handle for implicit invitation: %s", err)
		}
	}(internalMsg, s.ActionEvent())

	return connRecord.ConnectionID, nil
}

func createDIDCommMsg(invitation *Invitation) (*service.DIDCommMsg, error) {
	payload, err := json.Marshal(invitation)
	if err != nil {
		return nil, fmt.Errorf("marshal invitation: %w", err)
	}

	return service.NewDIDCommMsg(payload)
}
