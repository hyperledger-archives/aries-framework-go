/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
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
	// stateOOBRequested the outofband protocol state name to determine specific event
	stateOOBRequested = "requested"
)

const (
	maxIntroducees         = 2
	participantsKey        = "participants_%s_%s"
	stateNameKey           = "state_name_"
	transitionalPayloadKey = "transitionalPayload_%s"
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

// Action contains helpful information about action
type Action struct {
	// Protocol instance ID
	PIID string
	Msg  service.DIDCommMsgMap
}

// transitionalPayload keeps payload needed for Continue function to proceed with the action
type transitionalPayload struct {
	// Protocol instance ID
	PIID      string
	StateName string
	Msg       service.DIDCommMsgMap
	MyDID     string
	TheirDID  string
}

// metaData type to store data for internal usage
type metaData struct {
	transitionalPayload
	state        state
	msgClone     service.DIDCommMsg
	participants []*participant
	rejected     bool
	inbound      bool
	// err is used to determine whether callback was stopped
	// e.g the user received an action event and executes Stop(err) function
	// in that case `err` is equal to `err` which was passing to Stop function
	err error
}

// Service for introduce protocol
type Service struct {
	service.Action
	service.Message
	store     storage.Store
	callbacks chan *metaData
	oobEvent  chan service.StateMsg
	messenger service.Messenger
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

	oobSvc, err := p.Service(outofband.Name)
	if err != nil {
		return nil, fmt.Errorf("load the %s service: %w", outofband.Name, err)
	}

	oobService, ok := oobSvc.(service.Event)
	if !ok {
		return nil, fmt.Errorf("cast service to service.Event")
	}

	svc := &Service{
		messenger: p.Messenger(),
		store:     store,
		callbacks: make(chan *metaData),
		oobEvent:  make(chan service.StateMsg),
	}

	if err = oobService.RegisterMsgEvent(svc.oobEvent); err != nil {
		return nil, fmt.Errorf("oob register msg event: %w", err)
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
			// if no error or it was rejected do handle
			if msg.err == nil || msg.rejected {
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
		case event := <-s.oobEvent:
			if err := s.OOBMessageReceived(event); err != nil {
				logger.Errorf("listener oob message received: %s", err)
			}
		}
	}
}

func logInternalError(err error) {
	if _, ok := err.(customError); !ok {
		logger.Errorf("go to abandoning: %v", err)
	}
}

func getPIID(msg service.DIDCommMsg) (string, error) {
	piID := msg.Metadata()[metaPIID]
	if piID, ok := piID.(string); ok && piID != "" {
		return piID, nil
	}

	return threadID(msg)
}

func threadID(msg service.DIDCommMsg) (string, error) {
	if pthID := msg.ParentThreadID(); pthID != "" {
		return pthID, nil
	}

	thID, err := msg.ThreadID()
	if errors.Is(err, service.ErrThreadIDNotFound) {
		msg.(service.DIDCommMsgMap)["@id"] = uuid.New().String()
		return msg.(service.DIDCommMsgMap)["@id"].(string), nil
	}

	return thID, err
}

func (s *Service) doHandle(msg service.DIDCommMsg, outbound bool) (*metaData, error) {
	piID, err := getPIID(msg)
	if err != nil {
		return nil, fmt.Errorf("piID: %w", err)
	}

	stateName, err := s.currentStateName(piID)
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
		transitionalPayload: transitionalPayload{
			StateName: next.Name(),
			Msg:       msg.(service.DIDCommMsgMap),
			PIID:      piID,
		},
		state:    next,
		msgClone: msg.Clone(),
	}, nil
}

// OOBMessageReceived is used to finish the state machine
// the function should be called by the out-of-band service after receiving an oob message
func (s *Service) OOBMessageReceived(msg service.StateMsg) error {
	if msg.StateID != stateOOBRequested || msg.Type != service.PostState || msg.Msg.ParentThreadID() == "" {
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

	md, err := s.doHandle(msg, false)
	if err != nil {
		return "", fmt.Errorf("doHandle: %w", err)
	}

	// sets inbound payload
	md.inbound = true
	md.MyDID = myDID
	md.TheirDID = theirDID

	// trigger action event based on message type for inbound messages
	if canTriggerActionEvents(msg) {
		err = s.saveTransitionalPayload(md.PIID, md.transitionalPayload)
		if err != nil {
			return "", fmt.Errorf("save transitional payload: %w", err)
		}

		aEvent <- s.newDIDCommActionMsg(md)

		return md.PIID, nil
	}

	// if no action event is triggered, continue the execution
	return md.PIID, s.handle(md)
}

// HandleOutbound handles outbound message (introduce protocol)
func (s *Service) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) error {
	md, err := s.doHandle(msg, true)
	if err != nil {
		return fmt.Errorf("doHandle: %w", err)
	}

	// sets outbound payload
	md.MyDID = myDID
	md.TheirDID = theirDID

	return s.handle(md)
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
		// if introducee received Proposal rejected must be true
		if md.Msg.Type() == ProposalMsgType {
			md.rejected = true
		}

		md.err = err
		s.processCallback(md)
	}

	return service.DIDCommAction{
		ProtocolName: Introduce,
		Message:      md.msgClone,
		Continue: func(opt interface{}) {
			if fn, ok := opt.(Opt); ok {
				fn(md.Msg.Metadata())
			}

			if md.Msg.Type() == RequestMsgType {
				if md.Msg.Metadata()[metaRecipients] == nil {
					md.err = errors.New("no recipients")
				}
			}

			if err := s.deleteTransitionalPayload(md.PIID); err != nil {
				logger.Errorf("delete transitional payload", err)
			}

			s.processCallback(md)
		},
		Stop: func(err error) { actionStop(customError{error: err}) },
	}
}

// Continue allows proceeding with the action by the piID
func (s *Service) Continue(piID string, opt Opt) error {
	tPayload, err := s.getTransitionalPayload(piID)
	if err != nil {
		return fmt.Errorf("get transitional payload: %w", err)
	}

	md := &metaData{
		transitionalPayload: *tPayload,
		state:               stateFromName(tPayload.StateName),
		msgClone:            tPayload.Msg.Clone(),
		inbound:             true,
	}

	if opt != nil {
		opt(md.Msg.Metadata())
	}

	if md.Msg.Type() == RequestMsgType {
		if md.Msg.Metadata()[metaRecipients] == nil {
			return errors.New("no recipients")
		}
	}

	if err := s.deleteTransitionalPayload(md.PIID); err != nil {
		logger.Errorf("delete transitional payload", err)
	}

	s.processCallback(md)

	return nil
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

func (s *Service) currentStateName(piID string) (string, error) {
	src, err := s.store.Get(stateNameKey + piID)
	if errors.Is(err, storage.ErrDataNotFound) {
		return stateNameStart, nil
	}

	return string(src), err
}

// Actions returns actions for the async usage
func (s *Service) Actions() ([]Action, error) {
	records := s.store.Iterator(
		fmt.Sprintf(transitionalPayloadKey, ""),
		fmt.Sprintf(transitionalPayloadKey, storage.EndKeySuffix),
	)
	defer records.Release()

	var actions []Action

	for records.Next() {
		if records.Error() != nil {
			return nil, records.Error()
		}

		var action Action
		if err := json.Unmarshal(records.Value(), &action); err != nil {
			return nil, fmt.Errorf("unmarshal: %w", err)
		}

		actions = append(actions, action)
	}

	return actions, nil
}

func (s *Service) deleteTransitionalPayload(id string) error {
	return s.store.Delete(fmt.Sprintf(transitionalPayloadKey, id))
}

func (s *Service) saveTransitionalPayload(id string, data transitionalPayload) error {
	src, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal transitional payload: %w", err)
	}

	return s.store.Put(fmt.Sprintf(transitionalPayloadKey, id), src)
}

func (s *Service) getTransitionalPayload(id string) (*transitionalPayload, error) {
	src, err := s.store.Get(fmt.Sprintf(transitionalPayloadKey, id))
	if err != nil {
		return nil, fmt.Errorf("store get: %w", err)
	}

	t := &transitionalPayload{}

	err = json.Unmarshal(src, t)
	if err != nil {
		return nil, fmt.Errorf("unmarshal transitional payload: %w", err)
	}

	return t, err
}

func (s *Service) saveStateName(piID, stateName string) error {
	return s.store.Put(stateNameKey+piID, []byte(stateName))
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
	if md.Msg.Metadata()[metaSkipProposal] == nil {
		return false
	}

	return md.Msg.Metadata()[metaSkipProposal].(bool)
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

	if err := s.saveStateName(md.PIID, stateName); err != nil {
		return fmt.Errorf("failed to persist state %s: %w", stateName, err)
	}

	for _, action := range actions {
		if err := action(); err != nil {
			return err
		}
	}

	return nil
}

func contextOOBMessage(msg service.DIDCommMsg) map[string]interface{} {
	var oobMsg map[string]interface{}

	switch v := msg.Metadata()[metaOOBMessage].(type) {
	case service.DIDCommMsgMap:
		oobMsg = v.Clone()

		for k := range v.Metadata() {
			delete(oobMsg, k)
		}
	case map[string]interface{}:
		oobMsg = v
	}

	return oobMsg
}

type participant struct {
	OOBMessage map[string]interface{}
	Approve    bool
	MessageID  string
	MyDID      string
	TheirDID   string
	ThreadID   string
	CreatedAt  time.Time
}

func (s *Service) saveResponse(md *metaData) error {
	// ignore if message is not response
	if md.Msg.Type() != ResponseMsgType {
		return nil
	}

	// checks whether response was already handled
	for _, p := range md.participants {
		if p.MessageID == md.Msg.ID() {
			return nil
		}
	}

	r := Response{}
	if err := md.Msg.Decode(&r); err != nil {
		return err
	}

	thID, err := md.Msg.ThreadID()
	if err != nil {
		return fmt.Errorf("threadID: %w", err)
	}

	err = s.saveParticipant(md.PIID, &participant{
		OOBMessage: r.OOBMessage,
		Approve:    r.Approve,
		MessageID:  md.Msg.ID(),
		MyDID:      md.MyDID,
		TheirDID:   md.TheirDID,
		ThreadID:   thID,
		CreatedAt:  time.Now(),
	})
	if err != nil {
		return fmt.Errorf("save participant: %w", err)
	}

	md.participants, err = s.getParticipants(md.PIID)

	return err
}

func (s *Service) saveParticipant(piID string, p *participant) error {
	src, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return s.store.Put(fmt.Sprintf(participantsKey, piID, uuid.New().String()), src)
}

func (s *Service) getParticipants(piID string) ([]*participant, error) {
	records := s.store.Iterator(fmt.Sprintf(participantsKey, piID, ""),
		fmt.Sprintf(participantsKey, piID, storage.EndKeySuffix))
	defer records.Release()

	var participants []*participant

	for records.Next() {
		if records.Error() != nil {
			return nil, records.Error()
		}

		var participant *participant
		if err := json.Unmarshal(records.Value(), &participant); err != nil {
			return nil, fmt.Errorf("unmarshal: %w", err)
		}

		participants = append(participants, participant)
	}

	sort.Slice(participants, func(i, j int) bool {
		return participants[i].CreatedAt.UnixNano() < participants[j].CreatedAt.UnixNano()
	})

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
