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
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	// Name defines the protocol name.
	Name = "present-proof"
	// Spec defines the protocol spec.
	Spec = "https://didcomm.org/present-proof/2.0/"
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
	internalDataKey        = "internal_data_"
	transitionalPayloadKey = "transitionalPayload_%s"
)

// nolint:gochecknoglobals
var (
	logger         = log.New("aries-framework/presentproof/service")
	initialHandler = HandlerFunc(func(_ Metadata) error {
		return nil
	})
	errProtocolStopped = errors.New("protocol was stopped")
)

// customError is a wrapper to determine custom error against internal error.
type customError struct{ error }

// transitionalPayload keeps payload needed for Continue function to proceed with the action.
type transitionalPayload struct {
	Action
	StateName   string
	AckRequired bool
}

// metaData type to store data for internal usage.
type metaData struct {
	transitionalPayload
	state               state
	presentationNames   []string
	properties          map[string]interface{}
	msgClone            service.DIDCommMsg
	presentation        *Presentation
	proposePresentation *ProposePresentation
	request             *RequestPresentation
	// err is used to determine whether callback was stopped
	// e.g the user received an action event and executes Stop(err) function
	// in that case `err` is equal to `err` which was passing to Stop function
	err error
}

func (md *metaData) Message() service.DIDCommMsg {
	return md.msgClone
}

func (md *metaData) Presentation() *Presentation {
	return md.presentation
}

func (md *metaData) ProposePresentation() *ProposePresentation {
	return md.proposePresentation
}

func (md *metaData) RequestPresentation() *RequestPresentation {
	return md.request
}

func (md *metaData) PresentationNames() []string {
	return md.presentationNames
}

func (md *metaData) StateName() string {
	return md.state.Name()
}

func (md *metaData) Properties() map[string]interface{} {
	return md.properties
}

// Action contains helpful information about action.
type Action struct {
	// Protocol instance ID
	PIID     string
	Msg      service.DIDCommMsgMap
	MyDID    string
	TheirDID string
}

// Opt describes option signature for the Continue function.
type Opt func(md *metaData)

// WithPresentation allows providing Presentation message
// USAGE: This message can be provided after receiving a Request message.
func WithPresentation(msg *Presentation) Opt {
	return func(md *metaData) {
		md.presentation = msg
	}
}

// WithProposePresentation allows providing ProposePresentation message
// USAGE: This message can be provided after receiving a Request message.
func WithProposePresentation(msg *ProposePresentation) Opt {
	return func(md *metaData) {
		md.proposePresentation = msg
	}
}

// WithRequestPresentation allows providing RequestPresentation message
// USAGE: This message can be provided after receiving a propose message.
func WithRequestPresentation(msg *RequestPresentation) Opt {
	return func(md *metaData) {
		md.request = msg
	}
}

// WithFriendlyNames allows providing names for the presentations.
func WithFriendlyNames(names ...string) Opt {
	return func(md *metaData) {
		md.presentationNames = names
	}
}

// Provider contains dependencies for the protocol and is typically created by using aries.Context()
type Provider interface {
	Messenger() service.Messenger
	StorageProvider() storage.Provider
}

// Service for the presentproof protocol.
type Service struct {
	service.Action
	service.Message
	store      storage.Store
	callbacks  chan *metaData
	messenger  service.Messenger
	middleware Handler
}

// New returns the presentproof service.
func New(p Provider) (*Service, error) {
	store, err := p.StorageProvider().OpenStore(Name)
	if err != nil {
		return nil, err
	}

	svc := &Service{
		messenger:  p.Messenger(),
		store:      store,
		callbacks:  make(chan *metaData),
		middleware: initialHandler,
	}

	// start the listener
	go svc.startInternalListener()

	return svc, nil
}

// Use allows providing middlewares.
func (s *Service) Use(items ...Middleware) {
	var handler Handler = initialHandler
	for i := len(items) - 1; i >= 0; i-- {
		handler = items[i](handler)
	}

	s.middleware = handler
}

// HandleInbound handles inbound message (presentproof protocol).
func (s *Service) HandleInbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	logger.Debugf("service.HandleInbound() input: msg=%+v myDID=%s theirDID=%s", msg, myDID, theirDID)

	msgMap := msg.Clone()

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
	if canReply && canTriggerActionEvents(msgMap) {
		err = s.saveTransitionalPayload(md.PIID, md.transitionalPayload)
		if err != nil {
			return "", fmt.Errorf("save transitional payload: %w", err)
		}
		aEvent <- s.newDIDCommActionMsg(md)

		return "", nil
	}

	thid, err := msgMap.ThreadID()
	if err != nil {
		return "", fmt.Errorf("failed to obtain the message's threadID : %w", err)
	}

	// if no action event is triggered, continue the execution
	return thid, s.handle(md)
}

// HandleOutbound handles outbound message (presentproof protocol).
func (s *Service) HandleOutbound(_ service.DIDCommMsg, _, _ string) (string, error) {
	return "", errors.New("not implemented")
}

func (s *Service) getCurrentInternalDataAndPIID(msg service.DIDCommMsg) (string, *internalData, error) {
	piID, err := getPIID(msg)
	if errors.Is(err, service.ErrThreadIDNotFound) {
		piID = uuid.New().String()

		return piID, &internalData{StateName: stateNameStart}, msg.SetID(piID)
	}

	if err != nil {
		return "", nil, fmt.Errorf("piID: %w", err)
	}

	data, err := s.currentInternalData(piID)
	if err != nil {
		return "", nil, fmt.Errorf("current internal data: %w", err)
	}

	return piID, data, nil
}

func (s *Service) doHandle(msg service.DIDCommMsgMap) (*metaData, error) {
	piID, data, err := s.getCurrentInternalDataAndPIID(msg)
	if err != nil {
		return nil, fmt.Errorf("current internal data and PIID: %w", err)
	}

	current := stateFromName(data.StateName)

	next, err := nextState(msg)
	if err != nil {
		return nil, fmt.Errorf("nextState: %w", err)
	}

	if !current.CanTransitionTo(next) {
		return nil, fmt.Errorf("invalid state transition: %s -> %s", current.Name(), next.Name())
	}

	return &metaData{
		transitionalPayload: transitionalPayload{
			StateName:   next.Name(),
			AckRequired: data.AckRequired,
			Action: Action{
				Msg:  msg,
				PIID: piID,
			},
		},
		properties: map[string]interface{}{},
		state:      next,
		msgClone:   msg.Clone(),
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

		logger.Errorf("failed to handle msgID=%s : %s", msg.Msg.ID(), msg.err)

		msg.state = &abandoned{Code: codeInternalError}

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

		// WARN: md.ackRequired is being modified by requestSent state
		data := &internalData{StateName: current.Name(), AckRequired: md.AckRequired}
		if err := s.saveInternalData(md.PIID, data); err != nil {
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

type internalData struct {
	AckRequired bool
	StateName   string
}

func (s *Service) saveInternalData(piID string, data *internalData) error {
	src, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return s.store.Put(internalDataKey+piID, src)
}

func (s *Service) currentInternalData(piID string) (*internalData, error) {
	src, err := s.store.Get(internalDataKey + piID)
	if errors.Is(err, storage.ErrDataNotFound) {
		return &internalData{StateName: stateNameStart}, nil
	}

	if err != nil {
		return nil, err
	}

	var data *internalData
	if err := json.Unmarshal(src, &data); err != nil {
		return nil, err
	}

	return data, nil
}

// nolint: gocyclo
// stateFromName returns the state by given name.
func stateFromName(name string) state {
	switch name {
	case stateNameStart:
		return &start{}
	case stateNameAbandoned:
		return &abandoned{}
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
		return &abandoned{}, nil
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

// canTriggerActionEvents checks if the incoming message can trigger an action event.
func canTriggerActionEvents(msg service.DIDCommMsg) bool {
	return msg.Type() == PresentationMsgType ||
		msg.Type() == ProposePresentationMsgType ||
		msg.Type() == RequestPresentationMsgType ||
		msg.Type() == ProblemReportMsgType
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

// Actions returns actions for the async usage.
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

// ActionContinue allows proceeding with the action by the piID.
func (s *Service) ActionContinue(piID string, opt Opt) error {
	tPayload, err := s.getTransitionalPayload(piID)
	if err != nil {
		return fmt.Errorf("get transitional payload: %w", err)
	}

	md := &metaData{
		transitionalPayload: *tPayload,
		state:               stateFromName(tPayload.StateName),
		msgClone:            tPayload.Msg.Clone(),
		properties:          map[string]interface{}{},
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

// ActionStop allows stopping the action by the piID.
func (s *Service) ActionStop(piID string, cErr error) error {
	tPayload, err := s.getTransitionalPayload(piID)
	if err != nil {
		return fmt.Errorf("get transitional payload: %w", err)
	}

	md := &metaData{
		transitionalPayload: *tPayload,
		state:               stateFromName(tPayload.StateName),
		msgClone:            tPayload.Msg.Clone(),
		properties:          map[string]interface{}{},
	}

	if err := s.deleteTransitionalPayload(md.PIID); err != nil {
		return fmt.Errorf("delete transitional payload: %w", err)
	}

	if cErr == nil {
		cErr = errProtocolStopped
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

// newDIDCommActionMsg creates new DIDCommAction message.
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

			if cErr == nil {
				cErr = errProtocolStopped
			}

			md.err = customError{error: cErr}
			s.processCallback(md)
		},
		Properties: newEventProps(md),
	}
}

func (s *Service) execute(next state, md *metaData) (state, stateAction, error) {
	md.state = next
	s.sendMsgEvents(md, next.Name(), service.PreState)

	defer s.sendMsgEvents(md, next.Name(), service.PostState)

	md.properties = newEventProps(md).All()

	if err := s.middleware.Handle(md); err != nil {
		return nil, nil, fmt.Errorf("middleware: %w", err)
	}

	return next.Execute(md)
}

// sendMsgEvents triggers the message events.
func (s *Service) sendMsgEvents(md *metaData, stateID string, stateType service.StateMsgType) {
	// trigger the message events
	for _, handler := range s.MsgEvents() {
		handler <- service.StateMsg{
			ProtocolName: Name,
			Type:         stateType,
			Msg:          md.msgClone,
			StateID:      stateID,
			Properties:   newEventProps(md),
		}
	}
}

// Name returns service name.
func (s *Service) Name() string {
	return Name
}

// Accept msg checks the msg type.
func (s *Service) Accept(msgType string) bool {
	switch msgType {
	case ProposePresentationMsgType, RequestPresentationMsgType,
		PresentationMsgType, AckMsgType, ProblemReportMsgType:
		return true
	}

	return false
}
