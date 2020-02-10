/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	// Introduce protocol name
	Introduce = "introduce"
	// IntroduceSpec defines the introduce spec
	IntroduceSpec = "https://didcomm.org/introduce/1.0/"
	// ProposalMsgType defines the introduce proposal message type.
	ProposalMsgType = IntroduceSpec + "proposal"
	// RequestMsgType defines the introduce request message type.
	RequestMsgType = IntroduceSpec + "request"
	// ResponseMsgType defines the introduce response message type.
	ResponseMsgType = IntroduceSpec + "response"
	// AckMsgType defines the introduce ack message type.
	AckMsgType = IntroduceSpec + "ack"
	// ProblemReportMsgType defines the introduce problem-report message type.
	ProblemReportMsgType = IntroduceSpec + "problem-report"
	// stateInvited the didexchange protocol state name to determine specific event
	stateInvited = "invited"
)

const (
	maxIntroducees  = 2
	participantsKey = "participants_"
)

var logger = log.New("aries-framework/introduce/service")

// customError is a wrapper to determine custom error against internal error
type customError struct{ error }

// Recipient keeps information needed for the service
// 'To' field is needed for the proposal message
// 'MyDID' and 'TheirDID' fields are needed for sending messages e.g report-problem, proposal, ack etc.
type Recipient struct {
	To       *To
	MyDID    string `json:"my_did,omitempty"`
	TheirDID string `json:"their_did,omitempty"`
}

// metaData type to store data for internal usage
type metaData struct {
	state        state
	msg          service.DIDCommMsg
	msgClone     service.DIDCommMsg
	participants []participant
	contextID    string
	disapprove   bool
	inbound      bool
	myDID        string
	theirDID     string
	// err is used to determine whether callback was stopped
	// e.g the user received an action event and executes Stop(err) function
	// in that case `err` is equal to `err` which was passing to Stop function
	err error
}

// Service for introduce protocol
type Service struct {
	service.Action
	service.Message
	store           storage.Store
	callbacks       chan *metaData
	didEvent        chan service.StateMsg
	didEventService service.Event
	messenger       service.Messenger
}

// Provider contains dependencies for the DID exchange protocol and is typically created by using aries.Context()
type Provider interface {
	Messenger() service.Messenger
	StorageProvider() storage.Provider
	Service(id string) (interface{}, error)
}

// New returns introduce service
func New(p Provider) (*Service, error) {
	store, err := p.StorageProvider().OpenStore(Introduce)
	if err != nil {
		return nil, err
	}

	didSvc, err := p.Service(didexchange.DIDExchange)
	if err != nil {
		return nil, fmt.Errorf("load the DIDExchange service: %w", err)
	}

	didService, ok := didSvc.(service.Event)
	if !ok {
		return nil, fmt.Errorf("cast service to service.Event")
	}

	svc := &Service{
		messenger:       p.Messenger(),
		store:           store,
		didEventService: didService,
		callbacks:       make(chan *metaData),
		didEvent:        make(chan service.StateMsg),
	}

	if err = svc.didEventService.RegisterMsgEvent(svc.didEvent); err != nil {
		return nil, fmt.Errorf("did register msg event: %w", err)
	}

	// start the listener
	go svc.startInternalListener()

	return svc, nil
}

// startInternalListener listens to messages in gochannel for callback messages from clients.
func (s *Service) startInternalListener() {
	for {
		select {
		case msg := <-s.callbacks:
			// if no error - do handle or it was disapproved
			if msg.err == nil || msg.disapprove {
				msg.err = s.handle(msg)
			}

			// no error - continue
			if msg.err == nil {
				continue
			}

			msg.state = &abandoning{Code: codeInternalError}

			logInternalError(msg.err)

			if err := s.handle(msg); err != nil {
				logger.Errorf("listener handle: %s", err)
			}
		case event := <-s.didEvent:
			if err := s.InvitationReceived(event); err != nil {
				logger.Errorf("listener invitation received: %s", err)
			}
		}
	}
}

func logInternalError(err error) {
	if _, ok := err.(customError); !ok {
		logger.Errorf("go to abandoning: %v", err)
	}
}

func contextID(msg service.DIDCommMsg) string {
	contextID := msg.Metadata()[metaContextID]
	if cID, ok := contextID.(string); ok && cID != "" {
		return cID
	}

	return threadID(msg)
}

func threadID(msg service.DIDCommMsg) string {
	if pthID := msg.ParentThreadID(); pthID != "" {
		return pthID
	}

	thID, err := msg.ThreadID()
	if errors.Is(err, service.ErrThreadIDNotFound) {
		msg.(service.DIDCommMsgMap)["@id"] = uuid.New().String()
		return msg.(service.DIDCommMsgMap)["@id"].(string)
	}

	if err != nil {
		panic(err)
	}

	return thID
}

func (s *Service) doHandle(msg service.DIDCommMsg, outbound bool) (*metaData, error) {
	var ctxID = contextID(msg)

	stateName, err := s.currentStateName(ctxID)
	if err != nil {
		return nil, fmt.Errorf("currentStateName: %w", err)
	}

	current := stateFromName(stateName)

	next, err := nextState(msg, outbound)
	if err != nil {
		return nil, fmt.Errorf("nextState: %w", err)
	}

	if !current.CanTransitionTo(next) {
		return nil, fmt.Errorf("invalid state transition: %s -> %s", current.Name(), next.Name())
	}

	return &metaData{
		state:     next,
		msg:       msg,
		msgClone:  msg.Clone(),
		contextID: ctxID,
	}, nil
}

// InvitationReceived is used to finish the state machine
// the function should be called by didexchange after receiving an invitation
func (s *Service) InvitationReceived(msg service.StateMsg) error {
	if msg.StateID != stateInvited || msg.Type != service.PostState || msg.Msg.ParentThreadID() == "" {
		return nil
	}

	// NOTE: the message is being used internally.
	// Do not modify the payload such as ID and Thread.
	_, err := s.HandleInbound(service.NewDIDCommMsgMap(&model.Ack{
		Type:   AckMsgType,
		ID:     uuid.New().String(),
		Thread: &decorator.Thread{ID: msg.Msg.ParentThreadID()},
	}), "internal", "internal")

	return err
}

// HandleInbound handles inbound message (introduce protocol)
func (s *Service) HandleInbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	aEvent := s.ActionEvent()

	// throw error if there is no action event registered for inbound messages
	if aEvent == nil {
		return "", errors.New("no clients are registered to handle the message")
	}

	mData, err := s.doHandle(msg, false)
	if err != nil {
		return "", fmt.Errorf("doHandle: %w", err)
	}

	// sets inbound payload
	mData.inbound = true
	mData.myDID = myDID
	mData.theirDID = theirDID

	// trigger action event based on message type for inbound messages
	if canTriggerActionEvents(msg) {
		aEvent <- s.newDIDCommActionMsg(mData)
		return "", nil
	}

	// if no action event is triggered, continue the execution
	return "", s.handle(mData)
}

// HandleOutbound handles outbound message (introduce protocol)
func (s *Service) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) error {
	mData, err := s.doHandle(msg, true)
	if err != nil {
		return fmt.Errorf("doHandle: %w", err)
	}

	// sets outbound payload
	mData.myDID = myDID
	mData.theirDID = theirDID

	return s.handle(mData)
}

// sendMsgEvents triggers the message events.
func (s *Service) sendMsgEvents(msg *service.StateMsg) {
	// trigger the message events
	for _, handler := range s.MsgEvents() {
		handler <- *msg
	}
}

// newDIDCommActionMsg creates new DIDCommAction message
func (s *Service) newDIDCommActionMsg(md *metaData) service.DIDCommAction {
	// create the message for the channel
	// trigger the registered action event
	actionStop := func(err error) {
		// if introducee received Proposal disapprove must be true
		if md.msg.Type() == ProposalMsgType {
			md.disapprove = true
		}

		md.err = err
		s.processCallback(md)
	}

	return service.DIDCommAction{
		ProtocolName: Introduce,
		Message:      md.msgClone,
		Continue: func(opt interface{}) {
			if fn, ok := opt.(Opt); ok {
				fn(md.msg.Metadata())
			}

			if md.msg.Type() == RequestMsgType {
				if md.msg.Metadata()[metaRecipients] == nil {
					md.err = errors.New("no recipients")
				}
			}

			s.processCallback(md)
		},
		Stop: func(err error) { actionStop(customError{error: err}) },
	}
}

func (s *Service) processCallback(msg *metaData) {
	// pass the callback data to internal channel. This is created to unblock consumer go routine and wrap the callback
	// channel internally.
	s.callbacks <- msg
}

func nextState(msg service.DIDCommMsg, outbound bool) (state, error) {
	switch msg.Type() {
	case RequestMsgType:
		if outbound {
			return &requesting{}, nil
		}

		return &arranging{}, nil
	case ProposalMsgType:
		if outbound {
			return &arranging{}, nil
		}

		return &deciding{}, nil
	case ResponseMsgType:
		return &arranging{}, nil
	case ProblemReportMsgType:
		return &abandoning{}, nil
	case AckMsgType:
		return &done{}, nil
	default:
		return nil, fmt.Errorf("unrecognized msgType: %s", msg.Type())
	}
}

func (s *Service) currentStateName(ctxID string) (string, error) {
	src, err := s.store.Get(ctxID)
	if errors.Is(err, storage.ErrDataNotFound) {
		return stateNameStart, nil
	}

	return string(src), err
}

func (s *Service) saveStateName(id, stateName string) error {
	return s.store.Put(id, []byte(stateName))
}

// nolint: gocyclo
// stateFromName returns the state by given name.
func stateFromName(name string) state {
	switch name {
	case stateNameNoop:
		return &noOp{}
	case stateNameStart:
		return &start{}
	case stateNameDone:
		return &done{}
	case stateNameArranging:
		return &arranging{}
	case stateNameDelivering:
		return &delivering{}
	case stateNameConfirming:
		return &confirming{}
	case stateNameAbandoning:
		return &abandoning{}
	case stateNameRequesting:
		return &requesting{}
	case stateNameDeciding:
		return &deciding{}
	case stateNameWaiting:
		return &waiting{}
	default:
		return &noOp{}
	}
}

// canTriggerActionEvents checks if the incoming message can trigger an action event
func canTriggerActionEvents(msg service.DIDCommMsg) bool {
	switch msg.Type() {
	case ProposalMsgType, RequestMsgType:
		return true
	}

	return false
}

func isNoOp(s state) bool {
	_, ok := s.(*noOp)
	return ok
}

// isSkipProposal is a helper function to determine whether this is skip proposal or not.
func isSkipProposal(md *metaData) bool {
	if md.msg.Metadata()[metaSkipProposal] == nil {
		return false
	}

	return md.msg.Metadata()[metaSkipProposal].(bool)
}

func (s *Service) handle(md *metaData) error {
	if err := s.saveResponse(md); err != nil {
		return err
	}

	var (
		current   = md.state
		actions   []stateAction
		stateName string
	)

	for !isNoOp(current) {
		stateName = current.Name()

		next, action, err := s.execute(current, md)
		if err != nil {
			return fmt.Errorf("execute: %w", err)
		}

		actions = append(actions, action)

		if !isNoOp(next) && !current.CanTransitionTo(next) {
			return fmt.Errorf("invalid state transition: %s --> %s", current.Name(), next.Name())
		}

		current = next
	}

	if err := s.saveStateName(md.contextID, stateName); err != nil {
		return fmt.Errorf("failed to persist state %s: %w", stateName, err)
	}

	for _, action := range actions {
		if action == nil {
			continue
		}

		if err := action(); err != nil {
			return err
		}
	}

	return nil
}

func contextInvitation(msg service.DIDCommMsg) *didexchange.Invitation {
	inv := &didexchange.Invitation{}

	switch v := msg.Metadata()[metaInvitation].(type) {
	case service.DIDCommMsgMap:
		if err := v.Decode(inv); err != nil {
			// should never happen, otherwise, the protocol logic is broken
			panic(err)
		}

		return inv
	case map[string]interface{}:
		if err := service.DIDCommMsgMap(v).Decode(inv); err != nil {
			// should never happen, otherwise, the protocol logic is broken
			panic(err)
		}

		return inv
	}

	return nil
}

type participant struct {
	Invitation *didexchange.Invitation
	Approve    bool
	MessageID  string
	MyDID      string
	TheirDID   string
	ThreadID   string
}

func (s *Service) saveResponse(md *metaData) error {
	// ignore if message is not response
	if md.msg.Type() != ResponseMsgType {
		return nil
	}

	// checks whether response was already handled
	for _, p := range md.participants {
		if p.MessageID == md.msg.ID() {
			return nil
		}
	}

	r := Response{}
	if err := md.msg.Decode(&r); err != nil {
		return err
	}

	thID, err := md.msg.ThreadID()
	if err != nil {
		return fmt.Errorf("threadID: %w", err)
	}

	var ctxID = contextID(md.msg)

	md.participants, err = s.getParticipants(ctxID)
	if err != nil {
		return fmt.Errorf("getParticipants: %w", err)
	}

	md.participants = append(md.participants, participant{
		Invitation: r.Invitation,
		Approve:    r.Approve,
		MessageID:  md.msg.ID(),
		MyDID:      md.myDID,
		TheirDID:   md.theirDID,
		ThreadID:   thID,
	})

	return s.saveParticipants(ctxID, md.participants)
}

func (s *Service) saveParticipants(ctxID string, participants []participant) error {
	src, err := json.Marshal(participants)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return s.store.Put(participantsKey+ctxID, src)
}

func (s *Service) getParticipants(ctxID string) ([]participant, error) {
	src, err := s.store.Get(participantsKey + ctxID)
	if errors.Is(err, storage.ErrDataNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("store get: %w", err)
	}

	var participants []participant

	if err := json.Unmarshal(src, &participants); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	return participants, nil
}

func (s *Service) execute(next state, md *metaData) (state, stateAction, error) {
	s.sendMsgEvents(&service.StateMsg{
		ProtocolName: Introduce,
		Type:         service.PreState,
		Msg:          md.msgClone,
		StateID:      next.Name(),
	})

	var (
		followup state
		err      error
		action   func() error
	)

	if md.inbound {
		followup, action, err = next.ExecuteInbound(s.messenger, md)
	} else {
		followup, action, err = next.ExecuteOutbound(s.messenger, md)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("execute state %s %w", next.Name(), err)
	}

	s.sendMsgEvents(&service.StateMsg{
		ProtocolName: Introduce,
		Type:         service.PostState,
		Msg:          md.msgClone,
		StateID:      next.Name(),
	})

	return followup, action, nil
}

// Name returns service name
func (s *Service) Name() string {
	return Introduce
}

// Accept msg checks the msg type
func (s *Service) Accept(msgType string) bool {
	switch msgType {
	case ProposalMsgType, RequestMsgType, ResponseMsgType, AckMsgType, ProblemReportMsgType:
		return true
	}

	return false
}
