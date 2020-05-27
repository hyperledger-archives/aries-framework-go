/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

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
	// Name defines the protocol name
	Name = "issue-credential"
	// Spec defines the protocol spec
	Spec = "https://didcomm.org/issue-credential/2.0/"
	// ProposeCredentialMsgType defines the protocol propose-credential message type.
	ProposeCredentialMsgType = Spec + "propose-credential"
	// OfferCredentialMsgType defines the protocol offer-credential message type.
	OfferCredentialMsgType = Spec + "offer-credential"
	// RequestCredentialMsgType defines the protocol request-credential message type.
	RequestCredentialMsgType = Spec + "request-credential"
	// IssueCredentialMsgType defines the protocol issue-credential message type.
	IssueCredentialMsgType = Spec + "issue-credential"
	// AckMsgType defines the protocol ack message type.
	AckMsgType = Spec + "ack"
	// ProblemReportMsgType defines the protocol problem-report message type.
	ProblemReportMsgType = Spec + "problem-report"
	// CredentialPreviewMsgType defines the protocol credential-preview inner object type.
	CredentialPreviewMsgType = Spec + "credential-preview"
)

const (
	stateNameKey           = "state_name_"
	transitionalPayloadKey = "transitionalPayload_%s"
)

// nolint:gochecknoglobals
var (
	logger         = log.New("aries-framework/issuecredential/service")
	initialHandler = HandlerFunc(func(_ MetaData) error {
		return nil
	})
)

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
	state           state
	msgClone        service.DIDCommMsg
	inbound         bool
	credentialNames []string
	// keeps offer credential payload,
	// allows filling the message by providing an option function
	offerCredential   *OfferCredential
	proposeCredential *ProposeCredential
	issueCredential   *IssueCredential
	// err is used to determine whether callback was stopped
	// e.g the user received an action event and executes Stop(err) function
	// in that case `err` is equal to `err` which was passing to Stop function
	err error
}

func (md *metaData) Message() service.DIDCommMsg {
	return md.msgClone
}

func (md *metaData) OfferCredential() *OfferCredential {
	return md.offerCredential
}

func (md *metaData) ProposeCredential() *ProposeCredential {
	return md.proposeCredential
}

func (md *metaData) IssueCredential() *IssueCredential {
	return md.issueCredential
}

func (md *metaData) CredentialNames() []string {
	return md.credentialNames
}

func (md *metaData) StateName() string {
	return md.state.Name()
}

// Action contains helpful information about action
type Action struct {
	// Protocol instance ID
	PIID string                `json:"piid"`
	Msg  service.DIDCommMsgMap `json:"msg"`
}

// Opt describes option signature for the Continue function
type Opt func(md *metaData)

// WithProposeCredential allows providing ProposeCredential message
// USAGE: This message should be provided after receiving an OfferCredential message
func WithProposeCredential(msg *ProposeCredential) Opt {
	return func(md *metaData) {
		md.proposeCredential = msg
	}
}

// WithOfferCredential allows providing OfferCredential message
// USAGE: This message should be provided after receiving a ProposeCredential message
func WithOfferCredential(msg *OfferCredential) Opt {
	return func(md *metaData) {
		md.offerCredential = msg
	}
}

// WithIssueCredential allows providing IssueCredential message
// USAGE: This message should be provided after receiving a RequestCredential message
func WithIssueCredential(msg *IssueCredential) Opt {
	return func(md *metaData) {
		md.issueCredential = msg
	}
}

// WithFriendlyNames allows providing names for the credentials.
// USAGE: This function should be used when the Holder receives IssueCredential message
func WithFriendlyNames(names ...string) Opt {
	return func(md *metaData) {
		md.credentialNames = names
	}
}

// Provider contains dependencies for the protocol and is typically created by using aries.Context()
type Provider interface {
	Messenger() service.Messenger
	StorageProvider() storage.Provider
}

// Service for the issuecredential protocol
type Service struct {
	service.Action
	service.Message
	store      storage.Store
	callbacks  chan *metaData
	messenger  service.Messenger
	middleware Handler
}

// New returns the issuecredential service
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

// Use allows providing middlewares
func (s *Service) Use(items ...Middleware) {
	var handler Handler = initialHandler
	for i := len(items) - 1; i >= 0; i-- {
		handler = items[i](handler)
	}

	s.middleware = handler
}

// HandleInbound handles inbound message (issuecredential protocol)
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

		return "", nil
	}

	// if no action event is triggered, continue the execution
	return "", s.handle(md)
}

// HandleOutbound handles outbound message (issuecredential protocol)
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

func (s *Service) doHandle(msg service.DIDCommMsg, outbound bool) (*metaData, error) {
	piID, stateName, err := s.getCurrentStateNameAndPIID(msg)
	if err != nil {
		return nil, fmt.Errorf("getCurrentStateNameAndPIID: %w", err)
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
		if err := action(s.messenger); err != nil {
			return fmt.Errorf("action %s: %w", stateName, err)
		}
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
	case stateNameProposalReceived:
		return &proposalReceived{}
	case stateNameOfferSent:
		return &offerSent{}
	case stateNameRequestReceived:
		return &requestReceived{}
	case stateNameCredentialIssued:
		return &credentialIssued{}
	case stateNameProposalSent:
		return &proposalSent{}
	case stateNameOfferReceived:
		return &offerReceived{}
	case stateNameRequestSent:
		return &requestSent{}
	case stateNameCredentialReceived:
		return &credentialReceived{}
	default:
		return &noOp{}
	}
}

// nolint: gocyclo
func nextState(msg service.DIDCommMsg, outbound bool) (state, error) {
	switch msg.Type() {
	case ProposeCredentialMsgType:
		if outbound {
			return &proposalSent{}, nil
		}

		return &proposalReceived{}, nil
	case OfferCredentialMsgType:
		if outbound {
			return &offerSent{}, nil
		}

		return &offerReceived{}, nil
	case RequestCredentialMsgType:
		if outbound {
			return &requestSent{}, nil
		}

		return &requestReceived{}, nil
	case IssueCredentialMsgType:
		return &credentialReceived{}, nil
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
	return msg.Type() == ProposeCredentialMsgType ||
		msg.Type() == OfferCredentialMsgType ||
		msg.Type() == IssueCredentialMsgType ||
		msg.Type() == RequestCredentialMsgType
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
		inbound:             true,
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
		inbound:             true,
	}

	if err := s.deleteTransitionalPayload(md.PIID); err != nil {
		return fmt.Errorf("delete transitional payload: %w", err)
	}

	md.err = customError{error: cErr}
	s.processCallback(md)

	return nil
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
				logger.Errorf("delete transitional payload", err)
			}

			s.processCallback(md)
		},
		Stop: func(cErr error) {
			if err := s.deleteTransitionalPayload(md.PIID); err != nil {
				logger.Errorf("delete transitional payload", err)
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

	exec := next.ExecuteOutbound
	if md.inbound {
		exec = next.ExecuteInbound
	}

	if err := s.middleware.Handle(md); err != nil {
		return nil, nil, fmt.Errorf("middleware: %w", err)
	}

	return exec(md)
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
	case ProposeCredentialMsgType, OfferCredentialMsgType, RequestCredentialMsgType,
		IssueCredentialMsgType, AckMsgType, ProblemReportMsgType:
		return true
	}

	return false
}
