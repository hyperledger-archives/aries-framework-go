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

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

var logger = log.New("aries-framework/did-exchange/service")

const (
	// DIDExchange did exchange protocol
	DIDExchange = "didexchange"
	// PIURI is the did-exchange protocol identifier URI
	PIURI = "https://didcomm.org/didexchange/1.0"
	// InvitationMsgType defines the did-exchange invite message type.
	InvitationMsgType = PIURI + "/invitation"
	// RequestMsgType defines the did-exchange request message type.
	RequestMsgType = PIURI + "/request"
	// ResponseMsgType defines the did-exchange response message type.
	ResponseMsgType = PIURI + "/response"
	// AckMsgType defines the did-exchange ack message type.
	AckMsgType = PIURI + "/ack"
	// oobMsgType is the internal message type for the oob invitation that the didexchange service receives.
	oobMsgType = "oob-invitation"
)

// message type to store data for eventing. This is retrieved during callback.
type message struct {
	Msg           service.DIDCommMsgMap
	ThreadID      string
	Options       *options
	NextStateName string
	ConnRecord    *connection.Record
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
	Signer() legacykms.Signer
	VDRIRegistry() vdriapi.Registry
	Service(id string) (interface{}, error)
}

// stateMachineMsg is an internal struct used to pass data to state machine.
type stateMachineMsg struct {
	service.DIDCommMsg
	connRecord *connection.Record
	options    *options
}

// Service for DID exchange protocol
type Service struct {
	service.Action
	service.Message
	ctx             *context
	callbackChannel chan *message
	connectionStore *connectionStore
}

type context struct {
	outboundDispatcher dispatcher.Outbound
	signer             legacykms.Signer
	connectionStore    *connectionStore
	vdriRegistry       vdriapi.Registry
	routeSvc           mediator.ProtocolService
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

	s, err := prov.Service(mediator.Coordination)
	if err != nil {
		return nil, err
	}

	routeSvc, ok := s.(mediator.ProtocolService)
	if !ok {
		return nil, errors.New("cast service to Route Service failed")
	}

	const callbackChannelSize = 10

	svc := &Service{
		ctx: &context{
			outboundDispatcher: prov.OutboundDispatcher(),
			signer:             prov.Signer(),
			vdriRegistry:       prov.VDRIRegistry(),
			connectionStore:    connRecorder,
			routeSvc:           routeSvc,
		},
		// TODO channel size - https://github.com/hyperledger/aries-framework-go/issues/246
		callbackChannel: make(chan *message, callbackChannelSize),
		connectionStore: connRecorder,
	}

	// start the listener
	go svc.startInternalListener()

	return svc, nil
}

// HandleInbound handles inbound didexchange messages.
func (s *Service) HandleInbound(msg service.DIDCommMsg, _, _ string) (string, error) {
	logger.Debugf("receive inbound message : %s", msg)

	// fetch the thread id
	thID, err := msg.ThreadID()
	if err != nil {
		return "", err
	}

	// valid state transition and get the next state
	next, err := s.nextState(msg.Type(), thID)
	if err != nil {
		return "", fmt.Errorf("handle inbound - next state : %w", err)
	}

	// connection record
	connRecord, err := s.connectionRecord(msg)
	if err != nil {
		return "", fmt.Errorf("failed to fetch connection record : %w", err)
	}

	// TODO: get rid of this  msg.(service.DIDCommMsgMap)
	internalMsg := &message{
		Msg:           msg.(service.DIDCommMsgMap),
		ThreadID:      thID,
		NextStateName: next.Name(),
		ConnRecord:    connRecord,
	}

	go func(msg *message, aEvent chan<- service.DIDCommAction) {
		if err = s.handle(msg, aEvent); err != nil {
			logutil.LogError(logger, DIDExchange, "processMessage", err.Error(),
				logutil.CreateKeyValueString("msgType", msg.Msg.Type()),
				logutil.CreateKeyValueString("msgID", msg.Msg.ID()),
				logutil.CreateKeyValueString("connectionID", msg.ConnRecord.ConnectionID))
		}

		logutil.LogDebug(logger, DIDExchange, "processMessage", "success",
			logutil.CreateKeyValueString("msgType", msg.Msg.Type()),
			logutil.CreateKeyValueString("msgID", msg.Msg.ID()),
			logutil.CreateKeyValueString("connectionID", msg.ConnRecord.ConnectionID))
	}(internalMsg, s.ActionEvent())

	logutil.LogDebug(logger, DIDExchange, "handleInbound", "success",
		logutil.CreateKeyValueString("msgType", internalMsg.Msg.Type()),
		logutil.CreateKeyValueString("msgID", internalMsg.Msg.ID()),
		logutil.CreateKeyValueString("connectionID", internalMsg.ConnRecord.ConnectionID))

	return connRecord.ConnectionID, nil
}

// Name return service name
func (s *Service) Name() string {
	return DIDExchange
}

func findNamespace(msgType string) string {
	namespace := theirNSPrefix
	if msgType == InvitationMsgType || msgType == ResponseMsgType || msgType == oobMsgType {
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
func (s *Service) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) error {
	return errors.New("not implemented")
}

func (s *Service) nextState(msgType, thID string) (state, error) {
	logger.Debugf("msgType=%s thID=%s", msgType, thID)

	nsThID, err := connection.CreateNamespaceKey(findNamespace(msgType), thID)
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
	logger.Debugf("handling msg: %+v", msg)

	next, err := stateFromName(msg.NextStateName)
	if err != nil {
		return fmt.Errorf("invalid state name: %w", err)
	}

	for !isNoOp(next) {
		s.sendMsgEvents(&service.StateMsg{
			ProtocolName: DIDExchange,
			Type:         service.PreState,
			Msg:          msg.Msg,
			StateID:      next.Name(),
			Properties:   createEventProperties(msg.ConnRecord.ConnectionID, msg.ConnRecord.InvitationID),
		})
		logger.Debugf("sent pre event for state %s", next.Name())

		var (
			action           stateAction
			followup         state
			connectionRecord *connection.Record
		)

		connectionRecord, followup, action, err = next.ExecuteInbound(
			&stateMachineMsg{
				DIDCommMsg: msg.Msg,
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

		if err = s.update(msg.Msg.Type(), connectionRecord); err != nil {
			return fmt.Errorf("failed to persist state %s %w", next.Name(), err)
		}

		logger.Debugf("updated connection record %+v", connectionRecord)

		if err = action(); err != nil {
			return fmt.Errorf("failed to execute state action %s %w", next.Name(), err)
		}

		logger.Debugf("finish execute state action: %s", next.Name())

		prev := next
		next = followup
		haltExecution := false

		// trigger action event based on message type for inbound messages
		if msg.Msg.Type() != oobMsgType && canTriggerActionEvents(connectionRecord.State, connectionRecord.Namespace) {
			msg.NextStateName = next.Name()
			if err = s.sendActionEvent(msg, aEvent); err != nil {
				return fmt.Errorf("handle inbound: %w", err)
			}

			haltExecution = true
		}

		s.sendMsgEvents(&service.StateMsg{
			ProtocolName: DIDExchange,
			Type:         service.PostState,
			Msg:          msg.Msg,
			StateID:      prev.Name(),
			Properties:   createEventProperties(connectionRecord.ConnectionID, connectionRecord.InvitationID),
		})
		logger.Debugf("sent post event for state %s", prev.Name())

		if haltExecution {
			logger.Debugf("halted execution before state=%s", msg.NextStateName)
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
			Message:      internalMsg.Msg,
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
	return s.accept(connectionID, publicDID, label, StateIDInvited, "accept exchange invitation")
}

// AcceptExchangeRequest accepts/approves connection request.
func (s *Service) AcceptExchangeRequest(connectionID, publicDID, label string) error {
	return s.accept(connectionID, publicDID, label, StateIDRequested, "accept exchange request")
}

// RespondTo this inbound invitation and return with the new connection record's ID.
func (s *Service) RespondTo(i *OOBInvitation) (string, error) {
	i.Type = oobMsgType

	return s.HandleInbound(service.NewDIDCommMsgMap(i), "", "")
}

// SaveInvitation saves this invitation created by you.
func (s *Service) SaveInvitation(i *OOBInvitation) error {
	i.Type = oobMsgType

	err := s.connectionStore.SaveInvitation(i.ThreadID, i)
	if err != nil {
		return fmt.Errorf("failed to save oob invitation : %w", err)
	}

	return nil
}

func (s *Service) accept(connectionID, publicDID, label, stateID, errMsg string) error {
	msg, err := s.getEventTransientData(connectionID)
	if err != nil {
		return fmt.Errorf("failed to accept invitation for connectionID=%s : %s : %w", connectionID, errMsg, err)
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

func (s *Service) storeEventTransientData(msg *message) error {
	bytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("store transient data : %w", err)
	}

	return s.connectionStore.SaveEvent(msg.ConnRecord.ConnectionID, bytes)
}

func (s *Service) getEventTransientData(connectionID string) (*message, error) {
	val, err := s.connectionStore.GetEvent(connectionID)
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

// abandon updates the state to abandoned and trigger failure event.
func (s *Service) abandon(thID string, msg service.DIDCommMsg, processErr error) error {
	// update the state to abandoned
	nsThID, err := connection.CreateNamespaceKey(findNamespace(msg.Type()), thID)
	if err != nil {
		return err
	}

	connRec, err := s.connectionStore.GetConnectionRecordByNSThreadID(nsThID)
	if err != nil {
		return fmt.Errorf("unable to update the state to abandoned: %w", err)
	}

	connRec.State = (&abandoned{}).Name()

	err = s.update(msg.Type(), connRec)
	if err != nil {
		return fmt.Errorf("unable to update the state to abandoned: %w", err)
	}

	// send the message event
	s.sendMsgEvents(&service.StateMsg{
		ProtocolName: DIDExchange,
		Type:         service.PostState,
		Msg:          msg,
		StateID:      StateIDAbandoned,
		Properties:   createErrorEventProperties(connRec.ConnectionID, "", processErr),
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

func (s *Service) update(msgType string, connectionRecord *connection.Record) error {
	if (msgType == RequestMsgType && connectionRecord.State == StateIDRequested) ||
		(msgType == InvitationMsgType && connectionRecord.State == StateIDInvited) ||
		(msgType == oobMsgType && connectionRecord.State == StateIDInvited) {
		return s.connectionStore.saveConnectionRecordWithMapping(connectionRecord)
	}

	return s.connectionStore.saveConnectionRecord(connectionRecord)
}

func (s *Service) connectionRecord(msg service.DIDCommMsg) (*connection.Record, error) {
	switch msg.Type() {
	case oobMsgType:
		return s.oobInvitationMsgRecord(msg)
	case InvitationMsgType:
		return s.invitationMsgRecord(msg)
	case RequestMsgType:
		return s.requestMsgRecord(msg)
	case ResponseMsgType:
		return s.responseMsgRecord(msg)
	case AckMsgType:
		return s.ackMsgRecord(msg)
	}

	return nil, errors.New("invalid message type")
}

func (s *Service) oobInvitationMsgRecord(msg service.DIDCommMsg) (*connection.Record, error) {
	thID, err := msg.ThreadID()
	if err != nil {
		return nil, fmt.Errorf("failed to read the oobinvitation threadID : %w", err)
	}

	var oobInvitation OOBInvitation

	err = msg.Decode(&oobInvitation)
	if err != nil {
		return nil, fmt.Errorf("failed to decode the oob invitation : %w", err)
	}

	svc, err := s.ctx.getServiceBlock(&oobInvitation)
	if err != nil {
		return nil, fmt.Errorf("failed to get the did service block from oob invitation : %w", err)
	}

	connRecord := &connection.Record{
		ConnectionID:    generateRandomID(),
		ThreadID:        thID,
		ParentThreadID:  oobInvitation.ThreadID,
		State:           stateNameNull,
		InvitationID:    oobInvitation.ID,
		ServiceEndPoint: svc.ServiceEndpoint,
		RecipientKeys:   svc.RecipientKeys,
		TheirLabel:      oobInvitation.TheirLabel,
		Namespace:       findNamespace(msg.Type()),
	}

	publicDID, ok := oobInvitation.Target.(string)
	if ok {
		connRecord.Implicit = true
		connRecord.InvitationDID = publicDID
	}

	if err := s.connectionStore.saveConnectionRecord(connRecord); err != nil {
		return nil, err
	}

	return connRecord, nil
}

func (s *Service) invitationMsgRecord(msg service.DIDCommMsg) (*connection.Record, error) {
	thID, msgErr := msg.ThreadID()
	if msgErr != nil {
		return nil, msgErr
	}

	invitation := &Invitation{}

	err := msg.Decode(invitation)
	if err != nil {
		return nil, err
	}

	recKey, err := s.ctx.getInvitationRecipientKey(invitation)
	if err != nil {
		return nil, err
	}

	connRecord := &connection.Record{
		ConnectionID:    generateRandomID(),
		ThreadID:        thID,
		State:           stateNameNull,
		InvitationID:    invitation.ID,
		InvitationDID:   invitation.DID,
		ServiceEndPoint: invitation.ServiceEndpoint,
		RecipientKeys:   []string{recKey},
		TheirLabel:      invitation.Label,
		Namespace:       findNamespace(msg.Type()),
	}

	if err := s.connectionStore.saveConnectionRecord(connRecord); err != nil {
		return nil, err
	}

	return connRecord, nil
}

func (s *Service) requestMsgRecord(msg service.DIDCommMsg) (*connection.Record, error) {
	request := Request{}

	err := msg.Decode(&request)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling failed: %s", err)
	}

	invitationID := msg.ParentThreadID()
	if invitationID == "" {
		return nil, fmt.Errorf("missing parent thread ID on didexchange request with @id=%s", request.ID)
	}

	connRecord := &connection.Record{
		ConnectionID: generateRandomID(),
		ThreadID:     request.ID,
		State:        stateNameNull,
		TheirDID:     request.Connection.DID,
		InvitationID: invitationID,
		Namespace:    theirNSPrefix,
	}

	if err := s.connectionStore.saveConnectionRecord(connRecord); err != nil {
		return nil, err
	}

	return connRecord, nil
}

func (s *Service) responseMsgRecord(payload service.DIDCommMsg) (*connection.Record, error) {
	return s.fetchConnectionRecord(myNSPrefix, payload)
}

func (s *Service) ackMsgRecord(payload service.DIDCommMsg) (*connection.Record, error) {
	return s.fetchConnectionRecord(theirNSPrefix, payload)
}

func (s *Service) fetchConnectionRecord(nsPrefix string, payload service.DIDCommMsg) (*connection.Record, error) {
	msg := &struct {
		Thread decorator.Thread `json:"~thread,omitempty"`
	}{}

	err := payload.Decode(msg)
	if err != nil {
		return nil, err
	}

	key, err := connection.CreateNamespaceKey(nsPrefix, msg.Thread.ID)
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
	return (stateID == StateIDInvited && ns == myNSPrefix) || (stateID == StateIDRequested && ns == theirNSPrefix)
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
	connRecord := &connection.Record{
		ConnectionID:    generateRandomID(),
		ThreadID:        thID,
		State:           stateNameNull,
		InvitationDID:   inviterDID,
		Implicit:        true,
		ServiceEndPoint: dest.ServiceEndpoint,
		RecipientKeys:   dest.RecipientKeys,
		TheirLabel:      inviterLabel,
		Namespace:       findNamespace(InvitationMsgType),
	}

	if e := s.connectionStore.saveConnectionRecordWithMapping(connRecord); e != nil {
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

	// TODO: get rid of this  msg.(service.DIDCommMsgMap)
	next := &requested{}
	internalMsg := &message{
		Msg:           msg.(service.DIDCommMsgMap),
		ThreadID:      thID,
		NextStateName: next.Name(),
		ConnRecord:    connRecord,
	}
	internalMsg.Options = &options{publicDID: inviteeDID, label: inviteeLabel}

	go func(msg *message, aEvent chan<- service.DIDCommAction) {
		if err = s.handle(msg, aEvent); err != nil {
			logger.Errorf("error from handle for implicit invitation: %s", err)
		}
	}(internalMsg, s.ActionEvent())

	return connRecord.ConnectionID, nil
}

func createDIDCommMsg(invitation *Invitation) (service.DIDCommMsg, error) {
	payload, err := json.Marshal(invitation)
	if err != nil {
		return nil, fmt.Errorf("marshal invitation: %w", err)
	}

	return service.ParseDIDCommMsgMap(payload)
}
