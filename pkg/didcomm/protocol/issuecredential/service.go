/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// Name defines the protocol name.
	Name = "issue-credential"
	// SpecV2 defines the protocol spec V2.
	SpecV2 = "https://didcomm.org/issue-credential/2.0/"
	// ProposeCredentialMsgTypeV2 defines the protocol propose-credential message type.
	ProposeCredentialMsgTypeV2 = SpecV2 + "propose-credential"
	// OfferCredentialMsgTypeV2 defines the protocol offer-credential message type.
	OfferCredentialMsgTypeV2 = SpecV2 + "offer-credential"
	// RequestCredentialMsgTypeV2 defines the protocol request-credential message type.
	RequestCredentialMsgTypeV2 = SpecV2 + "request-credential"
	// IssueCredentialMsgTypeV2 defines the protocol issue-credential message type.
	IssueCredentialMsgTypeV2 = SpecV2 + "issue-credential"
	// AckMsgTypeV2 defines the protocol ack message type.
	AckMsgTypeV2 = SpecV2 + "ack"
	// ProblemReportMsgTypeV2 defines the protocol problem-report message type.
	ProblemReportMsgTypeV2 = SpecV2 + "problem-report"
	// CredentialPreviewMsgTypeV2 defines the protocol credential-preview inner object type.
	CredentialPreviewMsgTypeV2 = SpecV2 + "credential-preview"

	// SpecV3 defines the protocol spec V3.
	SpecV3 = "https://didcomm.org/issue-credential/3.0/"
	// ProposeCredentialMsgTypeV3 defines the protocol propose-credential message type.
	ProposeCredentialMsgTypeV3 = SpecV3 + "propose-credential"
	// OfferCredentialMsgTypeV3 defines the protocol offer-credential message type.
	OfferCredentialMsgTypeV3 = SpecV3 + "offer-credential"
	// RequestCredentialMsgTypeV3 defines the protocol request-credential message type.
	RequestCredentialMsgTypeV3 = SpecV3 + "request-credential"
	// IssueCredentialMsgTypeV3 defines the protocol issue-credential message type.
	IssueCredentialMsgTypeV3 = SpecV3 + "issue-credential"
	// AckMsgTypeV3 defines the protocol ack message type.
	AckMsgTypeV3 = SpecV3 + "ack"
	// ProblemReportMsgTypeV3 defines the protocol problem-report message type.
	ProblemReportMsgTypeV3 = SpecV3 + "problem-report"
	// CredentialPreviewMsgTypeV3 defines the protocol credential-preview inner object type.
	CredentialPreviewMsgTypeV3 = SpecV3 + "credential-preview"
)

const (
	stateNameKey           = "state_name_"
	transitionalPayloadKey = "transitionalPayload_%s"
)

// nolint:gochecknoglobals
var (
	logger         = log.New("aries-framework/issuecredential/service")
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
	StateName  string
	IsV3       bool
	Properties map[string]interface{}
}

// MetaData type to store data for internal usage.
type MetaData struct {
	transitionalPayload
	state           state
	msgClone        service.DIDCommMsg
	inbound         bool
	properties      map[string]interface{}
	credentialNames []string
	// keeps offer credential payload,
	// allows filling the message by providing an option function.
	offerCredentialV2   *OfferCredentialV2
	proposeCredentialV2 *ProposeCredentialV2
	requestCredentialV2 *RequestCredentialV2
	issueCredentialV2   *IssueCredentialV2
	offerCredentialV3   *OfferCredentialV3
	proposeCredentialV3 *ProposeCredentialV3
	requestCredentialV3 *RequestCredentialV3
	issueCredentialV3   *IssueCredentialV3
	// err is used to determine whether callback was stopped
	// e.g the user received an action event and executes Stop(err) function
	// in that case `err` is equal to `err` which was passing to Stop function.
	err error
}

// Message is the didcomm message.
func (md *MetaData) Message() service.DIDCommMsg {
	return md.msgClone
}

// OfferCredentialV2 didcomm message.
func (md *MetaData) OfferCredentialV2() *OfferCredentialV2 {
	return md.offerCredentialV2
}

// OfferCredentialV3 didcomm message.
func (md *MetaData) OfferCredentialV3() *OfferCredentialV3 {
	return md.offerCredentialV3
}

// ProposeCredentialV2 didcomm message.
func (md *MetaData) ProposeCredentialV2() *ProposeCredentialV2 {
	return md.proposeCredentialV2
}

// ProposeCredentialV3 didcomm message.
func (md *MetaData) ProposeCredentialV3() *ProposeCredentialV3 {
	return md.proposeCredentialV3
}

// RequestCredentialV2 didcomm message.
func (md *MetaData) RequestCredentialV2() *RequestCredentialV2 {
	return md.requestCredentialV2
}

// RequestCredentialV3 didcomm message.
func (md *MetaData) RequestCredentialV3() *RequestCredentialV3 {
	return md.requestCredentialV3
}

// IssueCredentialV2 didcomm message.
func (md *MetaData) IssueCredentialV2() *IssueCredentialV2 {
	return md.issueCredentialV2
}

// IssueCredentialV3 didcomm message.
func (md *MetaData) IssueCredentialV3() *IssueCredentialV3 {
	return md.issueCredentialV3
}

// CredentialNames are the names with which to save credentials with.
func (md *MetaData) CredentialNames() []string {
	return md.credentialNames
}

// StateName returns the name of the currently executing state.
func (md *MetaData) StateName() string {
	return md.state.Name()
}

// Properties returns metadata properties.
func (md *MetaData) Properties() map[string]interface{} {
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
type Opt func(md *MetaData)

// WithProposeCredential allows providing ProposeCredential message
// USAGE: This message should be provided after receiving an OfferCredential message.
func WithProposeCredential(msg *ProposeCredentialParams) Opt {
	return func(md *MetaData) {
		if md.IsV3 {
			md.proposeCredentialV3 = msg.AsV3()
		} else {
			md.proposeCredentialV2 = msg.AsV2()
		}
	}
}

// WithProposeCredentialV2 allows providing ProposeCredentialV2 message
// USAGE: This message should be provided after receiving an OfferCredentialV2 message.
func WithProposeCredentialV2(msg *ProposeCredentialV2) Opt {
	return func(md *MetaData) {
		md.proposeCredentialV2 = msg
	}
}

// WithProposeCredentialV3 allows providing ProposeCredentialV3 message
// USAGE: This message should be provided after receiving an OfferCredentialV3 message.
func WithProposeCredentialV3(msg *ProposeCredentialV3) Opt {
	return func(md *MetaData) {
		md.proposeCredentialV3 = msg
	}
}

// WithRequestCredential allows providing RequestCredential message
// USAGE: This message should be provided after receiving an OfferCredential message.
func WithRequestCredential(msg *RequestCredentialParams) Opt {
	return func(md *MetaData) {
		if md.IsV3 {
			md.requestCredentialV3 = msg.AsV3()
		} else {
			md.requestCredentialV2 = msg.AsV2()
		}
	}
}

// WithRequestCredentialV2 allows providing RequestCredentialV2 message
// USAGE: This message should be provided after receiving an OfferCredentialV2 message.
func WithRequestCredentialV2(msg *RequestCredentialV2) Opt {
	return func(md *MetaData) {
		md.requestCredentialV2 = msg
	}
}

// WithRequestCredentialV3 allows providing RequestCredentialV3 message
// USAGE: This message should be provided after receiving an OfferCredentialV3 message.
func WithRequestCredentialV3(msg *RequestCredentialV3) Opt {
	return func(md *MetaData) {
		md.requestCredentialV3 = msg
	}
}

// WithOfferCredential allows providing OfferCredential message
// USAGE: This message should be provided after receiving a ProposeCredential message.
func WithOfferCredential(msg *OfferCredentialParams) Opt {
	return func(md *MetaData) {
		if md.IsV3 {
			md.offerCredentialV3 = msg.AsV3()
		} else {
			md.offerCredentialV2 = msg.AsV2()
		}
	}
}

// WithOfferCredentialV2 allows providing OfferCredentialV2 message
// USAGE: This message should be provided after receiving a ProposeCredentialV2 message.
func WithOfferCredentialV2(msg *OfferCredentialV2) Opt {
	return func(md *MetaData) {
		md.offerCredentialV2 = msg
	}
}

// WithOfferCredentialV3 allows providing OfferCredentialV3 message
// USAGE: This message should be provided after receiving a ProposeCredentialV3 message.
func WithOfferCredentialV3(msg *OfferCredentialV3) Opt {
	return func(md *MetaData) {
		md.offerCredentialV3 = msg
	}
}

// WithIssueCredential allows providing IssueCredential message
// USAGE: This message should be provided after receiving a RequestCredential message.
func WithIssueCredential(msg *IssueCredentialParams) Opt {
	return func(md *MetaData) {
		if md.IsV3 {
			md.issueCredentialV3 = msg.AsV3()
		} else {
			md.issueCredentialV2 = msg.AsV2()
		}
	}
}

// WithIssueCredentialV2 allows providing IssueCredentialV2 message
// USAGE: This message should be provided after receiving a RequestCredentialV2 message.
func WithIssueCredentialV2(msg *IssueCredentialV2) Opt {
	return func(md *MetaData) {
		md.issueCredentialV2 = msg
	}
}

// WithIssueCredentialV3 allows providing IssueCredentialV3 message
// USAGE: This message should be provided after receiving a RequestCredentialV3 message.
func WithIssueCredentialV3(msg *IssueCredentialV3) Opt {
	return func(md *MetaData) {
		md.issueCredentialV3 = msg
	}
}

// WithFriendlyNames allows providing names for the credentials.
// USAGE: This function should be used when the Holder receives IssueCredentialV2 message.
func WithFriendlyNames(names ...string) Opt {
	return func(md *MetaData) {
		md.credentialNames = names
	}
}

// WithProperties allows providing custom properties.
func WithProperties(props map[string]interface{}) Opt {
	return func(md *MetaData) {
		if len(md.properties) == 0 {
			md.properties = props

			return
		}

		for k, v := range props {
			md.properties[k] = v
		}
	}
}

// Provider contains dependencies for the protocol and is typically created by using aries.Context().
type Provider interface {
	Messenger() service.Messenger
	StorageProvider() storage.Provider
}

// Service for the issuecredential protocol.
type Service struct {
	service.Action
	service.Message
	store       storage.Store
	callbacks   chan *MetaData
	messenger   service.Messenger
	middleware  Handler
	initialized bool
}

// New returns the issuecredential service.
func New(p Provider) (*Service, error) {
	svc := Service{}

	err := svc.Initialize(p)
	if err != nil {
		return nil, err
	}

	return &svc, nil
}

// Initialize initializes the Service. If Initialize succeeds, any further call is a no-op.
func (s *Service) Initialize(prov interface{}) error {
	if s.initialized {
		return nil
	}

	p, ok := prov.(Provider)
	if !ok {
		return fmt.Errorf("expected provider of type `%T`, got type `%T`", Provider(nil), p)
	}

	store, err := p.StorageProvider().OpenStore(Name)
	if err != nil {
		return err
	}

	err = p.StorageProvider().SetStoreConfig(Name, storage.StoreConfiguration{TagNames: []string{transitionalPayloadKey}})
	if err != nil {
		return fmt.Errorf("failed to set store config: %w", err)
	}

	s.messenger = p.Messenger()
	s.store = store
	s.callbacks = make(chan *MetaData)
	s.middleware = initialHandler

	// start the listener
	go s.startInternalListener()

	s.initialized = true

	return nil
}

// Use allows providing middlewares.
func (s *Service) Use(items ...Middleware) {
	var handler Handler = initialHandler
	for i := len(items) - 1; i >= 0; i-- {
		handler = items[i](handler)
	}

	s.middleware = handler
}

// AddMiddleware appends the given Middleware to the chain of middlewares.
func (s *Service) AddMiddleware(mw ...Middleware) {
	for i := len(mw) - 1; i >= 0; i-- {
		s.middleware = mw[i](s.middleware)
	}
}

// HandleInbound handles inbound message (issuecredential protocol).
func (s *Service) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
	logger.Debugf("handling inbound: %+v", msg)

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
	md.MyDID = ctx.MyDID()
	md.TheirDID = ctx.TheirDID()

	// trigger action event based on message type for inbound messages
	if canTriggerActionEvents(msg) {
		err = s.saveTransitionalPayload(md.PIID, &md.transitionalPayload)
		if err != nil {
			return "", fmt.Errorf("save transitional payload: %w", err)
		}

		aEvent <- s.newDIDCommActionMsg(md)

		return "", nil
	}

	// if no action event is triggered, continue the execution
	if err = s.handle(md); err != nil {
		return "", fmt.Errorf("handle inbound: %w", err)
	}

	return msg.ThreadID()
}

// HandleOutbound handles outbound message (issuecredential protocol).
func (s *Service) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	md, err := s.doHandle(msg, true)
	if err != nil {
		return "", fmt.Errorf("doHandle: %w", err)
	}

	// sets outbound payload
	md.MyDID = myDID
	md.TheirDID = theirDID

	if err = s.handle(md); err != nil {
		return "", fmt.Errorf("handle outbound: %w", err)
	}

	return msg.ThreadID()
}

func (s *Service) getCurrentStateNameAndPIID(msg service.DIDCommMsg) (string, string, error) {
	piID, err := getPIID(msg)
	if errors.Is(err, service.ErrThreadIDNotFound) {
		msg.SetID(uuid.New().String(), service.WithVersion(getDIDVersion(getVersion(msg.Type()))))

		return msg.ID(), stateNameStart, nil
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

func (s *Service) doHandle(msg service.DIDCommMsg, outbound bool) (*MetaData, error) {
	piID, stateName, err := s.getCurrentStateNameAndPIID(msg)
	if err != nil {
		return nil, fmt.Errorf("getCurrentStateNameAndPIID: %w", err)
	}

	protocolVersion := getVersion(msg.Type())

	current := stateFromName(stateName, protocolVersion)

	next, err := nextState(msg, outbound)
	if err != nil {
		return nil, fmt.Errorf("nextState: %w", err)
	}

	if !current.CanTransitionTo(next) {
		return nil, fmt.Errorf("invalid state transition: %s -> %s", current.Name(), next.Name())
	}

	return &MetaData{
		transitionalPayload: transitionalPayload{
			StateName: next.Name(),
			Action: Action{
				Msg:  msg.Clone(),
				PIID: piID,
			},
			IsV3:       protocolVersion == SpecV3,
			Properties: next.Properties(),
		},
		properties: next.Properties(),
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

		logger.Errorf("abandoning: %s", msg.err)
		msg.state = &abandoning{V: getVersion(msg.Msg.Type()), Code: codeInternalError}

		if err := s.handle(msg); err != nil {
			logger.Errorf("listener handle: %s", err)
		}
	}
}

func isNoOp(s state) bool {
	_, ok := s.(*noOp)
	return ok
}

func (s *Service) handle(md *MetaData) error {
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
func stateFromName(name, v string) state {
	switch name {
	case stateNameStart:
		return &start{}
	case stateNameAbandoning:
		return &abandoning{V: v}
	case stateNameDone:
		return &done{V: v}
	case stateNameProposalReceived:
		return &proposalReceived{V: v}
	case stateNameOfferSent:
		return &offerSent{V: v}
	case stateNameRequestReceived:
		return &requestReceived{V: v}
	case stateNameCredentialIssued:
		return &credentialIssued{V: v}
	case stateNameProposalSent:
		return &proposalSent{V: v}
	case stateNameOfferReceived:
		return &offerReceived{V: v}
	case stateNameRequestSent:
		return &requestSent{V: v}
	case stateNameCredentialReceived:
		return &credentialReceived{V: v}
	default:
		return &noOp{}
	}
}

func nextState(msg service.DIDCommMsg, outbound bool) (state, error) {
	switch msg.Type() {
	case ProposeCredentialMsgTypeV2, ProposeCredentialMsgTypeV3:
		if outbound {
			return &proposalSent{V: getVersion(msg.Type())}, nil
		}

		return &proposalReceived{V: getVersion(msg.Type())}, nil
	case OfferCredentialMsgTypeV2, OfferCredentialMsgTypeV3:
		if outbound {
			return &offerSent{V: getVersion(msg.Type())}, nil
		}

		return &offerReceived{V: getVersion(msg.Type())}, nil
	case RequestCredentialMsgTypeV2, RequestCredentialMsgTypeV3:
		if outbound {
			return &requestSent{V: getVersion(msg.Type())}, nil
		}

		return &requestReceived{V: getVersion(msg.Type())}, nil
	case IssueCredentialMsgTypeV2, IssueCredentialMsgTypeV3:
		return &credentialReceived{V: getVersion(msg.Type()), properties: redirectInfo(msg)}, nil
	case ProblemReportMsgTypeV2, ProblemReportMsgTypeV3:
		return &abandoning{V: getVersion(msg.Type()), properties: redirectInfo(msg)}, nil
	case AckMsgTypeV2, AckMsgTypeV3:
		return &done{V: getVersion(msg.Type())}, nil
	default:
		return nil, fmt.Errorf("unrecognized msgType: %s", msg.Type())
	}
}

func (s *Service) saveTransitionalPayload(id string, data *transitionalPayload) error {
	src, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal transitional payload: %w", err)
	}

	return s.store.Put(fmt.Sprintf(transitionalPayloadKey, id), src, storage.Tag{Name: transitionalPayloadKey})
}

// canTriggerActionEvents checks if the incoming message can trigger an action event.
func canTriggerActionEvents(msg service.DIDCommMsg) bool {
	return msg.Type() == ProposeCredentialMsgTypeV2 ||
		msg.Type() == OfferCredentialMsgTypeV2 ||
		msg.Type() == IssueCredentialMsgTypeV2 ||
		msg.Type() == RequestCredentialMsgTypeV2 ||
		msg.Type() == ProblemReportMsgTypeV2 ||
		msg.Type() == ProposeCredentialMsgTypeV3 ||
		msg.Type() == OfferCredentialMsgTypeV3 ||
		msg.Type() == IssueCredentialMsgTypeV3 ||
		msg.Type() == RequestCredentialMsgTypeV3 ||
		msg.Type() == ProblemReportMsgTypeV3
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

// ActionContinue allows proceeding with the action by the piID.
func (s *Service) ActionContinue(piID string, opts ...Opt) error {
	tPayload, err := s.getTransitionalPayload(piID)
	if err != nil {
		return fmt.Errorf("get transitional payload: %w", err)
	}

	md := &MetaData{
		transitionalPayload: *tPayload,
		state:               stateFromName(tPayload.StateName, getVersion(tPayload.Msg.Type())),
		msgClone:            tPayload.Msg.Clone(),
		inbound:             true,
		properties:          tPayload.Properties,
	}

	for _, opt := range opts {
		opt(md)
	}

	if err := s.deleteTransitionalPayload(md.PIID); err != nil {
		return fmt.Errorf("delete transitional payload: %w", err)
	}

	s.processCallback(md)

	return nil
}

// ActionStop allows stopping the action by the piID.
func (s *Service) ActionStop(piID string, cErr error, opts ...Opt) error {
	tPayload, err := s.getTransitionalPayload(piID)
	if err != nil {
		return fmt.Errorf("get transitional payload: %w", err)
	}

	md := &MetaData{
		transitionalPayload: *tPayload,
		state:               stateFromName(tPayload.StateName, getVersion(tPayload.Msg.Type())),
		msgClone:            tPayload.Msg.Clone(),
		inbound:             true,
		properties:          map[string]interface{}{},
	}

	for _, opt := range opts {
		opt(md)
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

// Actions returns actions for the async usage.
func (s *Service) Actions() ([]Action, error) {
	records, err := s.store.Query(transitionalPayloadKey)
	if err != nil {
		return nil, fmt.Errorf("failed to query the store: %w", err)
	}

	defer storage.Close(records, logger)

	var actions []Action

	more, err := records.Next()
	if err != nil {
		return nil, fmt.Errorf("failed to get next record: %w", err)
	}

	for more {
		value, errValue := records.Value()
		if errValue != nil {
			return nil, fmt.Errorf("failed to get value: %w", errValue)
		}

		var action Action
		if errUnmarshal := json.Unmarshal(value, &action); errUnmarshal != nil {
			return nil, fmt.Errorf("unmarshal: %w", errUnmarshal)
		}

		actions = append(actions, action)

		more, err = records.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to get next record: %w", err)
		}
	}

	return actions, nil
}

func (s *Service) processCallback(msg *MetaData) {
	// pass the callback data to internal channel. This is created to unblock consumer go routine and wrap the callback
	// channel internally.
	s.callbacks <- msg
}

// newDIDCommActionMsg creates new DIDCommAction message.
func (s *Service) newDIDCommActionMsg(md *MetaData) service.DIDCommAction {
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

			if cErr == nil {
				cErr = errProtocolStopped
			}

			md.err = customError{error: cErr}
			s.processCallback(md)
		},
		Properties: newEventProps(md),
	}
}

func getVersion(t string) string {
	if strings.HasPrefix(t, SpecV2) {
		return SpecV2
	}

	return SpecV3
}

func getDIDVersion(v string) service.Version {
	if v == SpecV3 {
		return service.V2
	}

	return service.V1
}

func (s *Service) execute(next state, md *MetaData) (state, stateAction, error) {
	md.state = next
	s.sendMsgEvents(md, next.Name(), service.PreState)

	defer s.sendMsgEvents(md, next.Name(), service.PostState)

	md.properties = newEventProps(md).All()

	if err := s.middleware.Handle(md); err != nil {
		return nil, nil, fmt.Errorf("middleware: %w", err)
	}

	exec := next.ExecuteOutbound
	if md.inbound {
		exec = next.ExecuteInbound
	}

	return exec(md)
}

// sendMsgEvents triggers the message events.
func (s *Service) sendMsgEvents(md *MetaData, stateID string, stateType service.StateMsgType) {
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
	case ProposeCredentialMsgTypeV2, OfferCredentialMsgTypeV2, RequestCredentialMsgTypeV2,
		IssueCredentialMsgTypeV2, AckMsgTypeV2, ProblemReportMsgTypeV2:
		return true
	case ProposeCredentialMsgTypeV3, OfferCredentialMsgTypeV3, RequestCredentialMsgTypeV3,
		IssueCredentialMsgTypeV3, AckMsgTypeV3, ProblemReportMsgTypeV3:
		return true
	}

	return false
}

// redirectInfo reads web redirect info decorator from given DIDComm Msg.
func redirectInfo(msg service.DIDCommMsg) map[string]interface{} {
	var redirectInfo struct {
		WebRedirectV2 map[string]interface{} `json:"~web-redirect,omitempty"`
		WebRedirectV3 map[string]interface{} `json:"web-redirect,omitempty"`
	}

	err := msg.Decode(&redirectInfo)
	if err != nil {
		// Don't fail protocol, in case of error while reading webredirect info.
		logger.Warnf("failed to decode redirect info: %s", err)
	}

	if msg.Type() == IssueCredentialMsgTypeV3 {
		return redirectInfo.WebRedirectV3
	}

	return redirectInfo.WebRedirectV2
}
