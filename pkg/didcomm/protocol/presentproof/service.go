/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	// Name defines the protocol name
	Name = "present-proof"
	// Spec defines the protocol spec
	Spec = "https://didcomm.org/present-proof/1.0/"
	// ProposePresentationMsgType defines the protocol propose-presentation message type.
	ProposePresentationMsgType = Spec + "propose-presentation"
	// RequestPresentationMsgType defines the protocol request-presentation message type.
	RequestPresentationMsgType = Spec + "request-presentation"
	// PresentationMsgType defines the protocol presentation message type.
	PresentationMsgType = Spec + "presentation"
	// AckMsgType defines the protocol ack message type.
	AckMsgType = Spec + "ack"
	// ProblemReportMsgType defines the protocol problem-report message type.
	ProblemReportMsgType = Spec + "problem-report"
	// PresentationPreviewMsgType defines the protocol presentation-preview inner object type.
	PresentationPreviewMsgType = Spec + "presentation-preview"
)

const (
	stateNameKey           = "state_name_"
	transitionalPayloadKey = "transitionalPayload_%s"
)

var logger = log.New("aries-framework/presentproof/service")

// customError is a wrapper to determine custom error against internal error
type customError struct{ error }

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
	state               state
	msgClone            service.DIDCommMsg
	presentation        *Presentation
	proposePresentation *ProposePresentation
	request             *RequestPresentation
	registryVDRI        vdri.Registry
	// err is used to determine whether callback was stopped
	// e.g the user received an action event and executes Stop(err) function
	// in that case `err` is equal to `err` which was passing to Stop function
	err error
}

// Action contains helpful information about action
type Action struct {
	// Protocol instance ID
	PIID string                `json:"piid"`
	Msg  service.DIDCommMsgMap `json:"msg"`
}

// Opt describes option signature for the Continue function
type Opt func(md *metaData)

// WithPresentation allows providing Presentation message
// USAGE: This message can be provided after receiving a Request message
func WithPresentation(msg *Presentation) Opt {
	return func(md *metaData) {
		md.presentation = msg
	}
}

// WithProposePresentation allows providing ProposePresentation message
// USAGE: This message can be provided after receiving a Request message
func WithProposePresentation(msg *ProposePresentation) Opt {
	return func(md *metaData) {
		md.proposePresentation = msg
	}
}

// WithRequestPresentation allows providing RequestPresentation message
// USAGE: This message can be provided after receiving a propose message
func WithRequestPresentation(msg *RequestPresentation) Opt {
	return func(md *metaData) {
		md.request = msg
	}
}

// Provider contains dependencies for the protocol and is typically created by using aries.Context()
type Provider interface {
	Messenger() service.Messenger
	StorageProvider() storage.Provider
	VDRIRegistry() vdri.Registry
}

// Service for the presentproof protocol
type Service struct {
	service.Action
	service.Message
	store        storage.Store
	callbacks    chan *metaData
	messenger    service.Messenger
	registryVDRI vdri.Registry
}

// New returns the presentproof service
func New(p Provider) (*Service, error) {
	store, err := p.StorageProvider().OpenStore(Name)
	if err != nil {
		return nil, err
	}

	svc := &Service{
		messenger:    p.Messenger(),
		registryVDRI: p.VDRIRegistry(),
		store:        store,
		callbacks:    make(chan *metaData),
	}

	// start the listener
	go svc.startInternalListener()

	return svc, nil
}

// HandleInbound handles inbound message (presentproof protocol)
func (s *Service) HandleInbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	msgMap, ok := msg.(service.DIDCommMsgMap)
	if !ok {
		return "", errors.New("bad assertion message is not DIDCommMsgMap")
	}

	aEvent := s.ActionEvent()

	canReply := canReplyTo(msgMap)

	if canReply && aEvent == nil {
		// throw error if there is no action event registered for inbound messages
		return "", errors.New("no clients are registered to handle the message")
	}

	md, err := s.doHandle(msgMap)
	if err != nil {
		return "", fmt.Errorf("doHandle: %w", err)
	}

	md.MyDID = myDID
	md.TheirDID = theirDID

	// trigger action event based on message type for inbound messages
	if canReply && canTriggerActionEvents(msg) {
		err = s.saveTransitionalPayload(md.PIID, md.transitionalPayload)
		if err != nil {
			return "", fmt.Errorf("save transitional payload: %w", err)
		}
		aEvent <- s.newDIDCommActionMsg(md)

		return "", nil
	}

	// if no action event is triggered, continue the execution
	return "", s.handle(md)
}

// HandleOutbound handles outbound message (presentproof protocol)
func (s *Service) HandleOutbound(_ service.DIDCommMsg, _, _ string) error {
	return nil
}

func (s *Service) getCurrentStateNameAndPIID(msg service.DIDCommMsg) (string, string, error) {
	piID, err := getPIID(msg)
	if errors.Is(err, service.ErrThreadIDNotFound) {
		piID = uuid.New().String()

		return piID, stateNameStart, msg.SetID(piID)
	}

	if err != nil {
		return "", "", fmt.Errorf("piID: %w", err)
	}

	stateName, err := s.currentStateName(piID)
	if err != nil {
		return "", "", fmt.Errorf("currentStateName: %w", err)
	}

	return piID, stateName, nil
}

func (s *Service) doHandle(msg service.DIDCommMsgMap) (*metaData, error) {
	piID, stateName, err := s.getCurrentStateNameAndPIID(msg)
	if err != nil {
		return nil, fmt.Errorf("getCurrentStateNameAndPIID: %w", err)
	}

	current := stateFromName(stateName)

	next, err := nextState(msg)
	if err != nil {
		return nil, fmt.Errorf("nextState: %w", err)
	}

	if !current.CanTransitionTo(next) {
		return nil, fmt.Errorf("invalid state transition: %s -> %s", current.Name(), next.Name())
	}

	return &metaData{
		transitionalPayload: transitionalPayload{
			StateName: next.Name(),
			Msg:       msg,
			PIID:      piID,
		},
		state:        next,
		msgClone:     msg.Clone(),
		registryVDRI: s.registryVDRI,
	}, nil
}

// startInternalListener listens to messages in go channel for callback messages from clients.
func (s *Service) startInternalListener() {
	for msg := range s.callbacks {
		// if no error do handle
		if msg.err == nil {
			msg.err = s.handle(msg)
		}

		// no error - continue
		if msg.err == nil {
			continue
		}

		msg.state = &abandoning{Code: codeInternalError}

		if err := s.handle(msg); err != nil {
			logger.Errorf("listener handle: %s", err)
		}
	}
}

func isNoOp(s state) bool {
	_, ok := s.(*noOp)
	return ok
}

func (s *Service) handle(md *metaData) error {
	var current = md.state

	for !isNoOp(current) {
		next, action, err := s.execute(current, md)
		if err != nil {
			return fmt.Errorf("execute: %w", err)
		}

		if !isNoOp(next) && !current.CanTransitionTo(next) {
			return fmt.Errorf("invalid state transition: %s --> %s", current.Name(), next.Name())
		}

		if err := s.saveStateName(md.PIID, current.Name()); err != nil {
			return fmt.Errorf("failed to persist state %s: %w", current.Name(), err)
		}

		if err := action(s.messenger); err != nil {
			return fmt.Errorf("action %s: %w", md.state.Name(), err)
		}

		current = next
	}

	return nil
}

func getPIID(msg service.DIDCommMsg) (string, error) {
	if pthID := msg.ParentThreadID(); pthID != "" {
		return pthID, nil
	}

	return msg.ThreadID()
}

func (s *Service) saveStateName(piID, stateName string) error {
	return s.store.Put(stateNameKey+piID, []byte(stateName))
}

func (s *Service) currentStateName(piID string) (string, error) {
	src, err := s.store.Get(stateNameKey + piID)
	if errors.Is(err, storage.ErrDataNotFound) {
		return stateNameStart, nil
	}

	return string(src), err
}

// nolint: gocyclo
// stateFromName returns the state by given name.
func stateFromName(name string) state {
	switch name {
	case stateNameStart:
		return &start{}
	case stateNameAbandoning:
		return &abandoning{}
	case stateNameDone:
		return &done{}
	case stateNameRequestSent:
		return &requestSent{}
	case stateNamePresentationReceived:
		return &presentationReceived{}
	case stateNameProposalReceived:
		return &proposalReceived{}
	case stateNameRequestReceived:
		return &requestReceived{}
	case stateNamePresentationSent:
		return &presentationSent{}
	case stateNameProposalSent:
		return &proposalSent{}
	default:
		return &noOp{}
	}
}

// nolint: gocyclo
func nextState(msg service.DIDCommMsgMap) (state, error) {
	canReply := canReplyTo(msg)

	switch msg.Type() {
	case RequestPresentationMsgType:
		if canReply {
			return &requestReceived{}, nil
		}

		return &requestSent{}, nil
	case ProposePresentationMsgType:
		if canReply {
			return &proposalReceived{}, nil
		}

		return &proposalSent{}, nil
	case PresentationMsgType:
		return &presentationReceived{}, nil
	case ProblemReportMsgType:
		return &abandoning{}, nil
	case AckMsgType:
		return &done{}, nil
	default:
		return nil, fmt.Errorf("unrecognized msgType: %s", msg.Type())
	}
}

func (s *Service) saveTransitionalPayload(id string, data transitionalPayload) error {
	src, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal transitional payload: %w", err)
	}

	return s.store.Put(fmt.Sprintf(transitionalPayloadKey, id), src)
}

// canTriggerActionEvents checks if the incoming message can trigger an action event
func canTriggerActionEvents(msg service.DIDCommMsg) bool {
	return msg.Type() == PresentationMsgType ||
		msg.Type() == ProposePresentationMsgType ||
		msg.Type() == RequestPresentationMsgType
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

func (s *Service) deleteTransitionalPayload(id string) error {
	return s.store.Delete(fmt.Sprintf(transitionalPayloadKey, id))
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
		var action Action
		if err := json.Unmarshal(records.Value(), &action); err != nil {
			return nil, fmt.Errorf("unmarshal: %w", err)
		}

		actions = append(actions, action)
	}

	if records.Error() != nil {
		return nil, records.Error()
	}

	return actions, nil
}

// ActionContinue allows proceeding with the action by the piID
func (s *Service) ActionContinue(piID string, opt Opt) error {
	tPayload, err := s.getTransitionalPayload(piID)
	if err != nil {
		return fmt.Errorf("get transitional payload: %w", err)
	}

	md := &metaData{
		transitionalPayload: *tPayload,
		state:               stateFromName(tPayload.StateName),
		msgClone:            tPayload.Msg.Clone(),
		registryVDRI:        s.registryVDRI,
	}

	if opt != nil {
		opt(md)
	}

	if err := s.deleteTransitionalPayload(md.PIID); err != nil {
		return fmt.Errorf("delete transitional payload: %w", err)
	}

	s.processCallback(md)

	return nil
}

// ActionStop allows stopping the action by the piID
func (s *Service) ActionStop(piID string, cErr error) error {
	tPayload, err := s.getTransitionalPayload(piID)
	if err != nil {
		return fmt.Errorf("get transitional payload: %w", err)
	}

	md := &metaData{
		transitionalPayload: *tPayload,
		state:               stateFromName(tPayload.StateName),
		msgClone:            tPayload.Msg.Clone(),
		registryVDRI:        s.registryVDRI,
	}

	if err := s.deleteTransitionalPayload(md.PIID); err != nil {
		return fmt.Errorf("delete transitional payload: %w", err)
	}

	md.err = customError{error: cErr}
	s.processCallback(md)

	return nil
}

func (s *Service) processCallback(msg *metaData) {
	// pass the callback data to internal channel. This is created to unblock consumer go routine and wrap the callback
	// channel internally.
	s.callbacks <- msg
}

// newDIDCommActionMsg creates new DIDCommAction message
func (s *Service) newDIDCommActionMsg(md *metaData) service.DIDCommAction {
	// create the message for the channel
	// trigger the registered action event
	return service.DIDCommAction{
		ProtocolName: Name,
		Message:      md.msgClone,
		Continue: func(opt interface{}) {
			if fn, ok := opt.(Opt); ok {
				fn(md)
			}

			if err := s.deleteTransitionalPayload(md.PIID); err != nil {
				logger.Errorf("continue: delete transitional payload: %v", err)
			}

			s.processCallback(md)
		},
		Stop: func(cErr error) {
			if err := s.deleteTransitionalPayload(md.PIID); err != nil {
				logger.Errorf("stop: delete transitional payload: %v", err)
			}

			md.err = customError{error: cErr}
			s.processCallback(md)
		},
	}
}

func (s *Service) execute(next state, md *metaData) (state, stateAction, error) {
	s.sendMsgEvents(&service.StateMsg{
		ProtocolName: Name,
		Type:         service.PreState,
		Msg:          md.msgClone,
		StateID:      next.Name(),
	})

	defer s.sendMsgEvents(&service.StateMsg{
		ProtocolName: Name,
		Type:         service.PostState,
		Msg:          md.msgClone,
		StateID:      next.Name(),
	})

	return next.Execute(md)
}

// sendMsgEvents triggers the message events.
func (s *Service) sendMsgEvents(msg *service.StateMsg) {
	// trigger the message events
	for _, handler := range s.MsgEvents() {
		handler <- *msg
	}
}

// Name returns service name
func (s *Service) Name() string {
	return Name
}

// Accept msg checks the msg type
func (s *Service) Accept(msgType string) bool {
	switch msgType {
	case ProposePresentationMsgType, RequestPresentationMsgType,
		PresentationMsgType, AckMsgType, ProblemReportMsgType:
		return true
	}

	return false
}
