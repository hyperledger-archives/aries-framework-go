/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// Name defines the protocol name.
	Name = "present-proof"
	// SpecV2 defines the protocol spec.
	SpecV2 = "https://didcomm.org/present-proof/2.0/"
	// ProposePresentationMsgTypeV2 defines the protocol propose-presentation message type.
	ProposePresentationMsgTypeV2 = SpecV2 + "propose-presentation"
	// RequestPresentationMsgTypeV2 defines the protocol request-presentation message type.
	RequestPresentationMsgTypeV2 = SpecV2 + "request-presentation"
	// PresentationMsgTypeV2 defines the protocol presentation message type.
	PresentationMsgTypeV2 = SpecV2 + "presentation"
	// AckMsgTypeV2 defines the protocol ack message type.
	AckMsgTypeV2 = SpecV2 + "ack"
	// ProblemReportMsgTypeV2 defines the protocol problem-report message type.
	ProblemReportMsgTypeV2 = SpecV2 + "problem-report"
	// PresentationPreviewMsgTypeV2 defines the protocol presentation-preview inner object type.
	PresentationPreviewMsgTypeV2 = SpecV2 + "presentation-preview"

	// SpecV3 defines the protocol spec.
	SpecV3 = "https://didcomm.org/present-proof/3.0/"
	// ProposePresentationMsgTypeV3 defines the protocol propose-presentation message type.
	ProposePresentationMsgTypeV3 = SpecV3 + "propose-presentation"
	// RequestPresentationMsgTypeV3 defines the protocol request-presentation message type.
	RequestPresentationMsgTypeV3 = SpecV3 + "request-presentation"
	// PresentationMsgTypeV3 defines the protocol presentation message type.
	PresentationMsgTypeV3 = SpecV3 + "presentation"
	// AckMsgTypeV3 defines the protocol ack message type.
	AckMsgTypeV3 = SpecV3 + "ack"
	// ProblemReportMsgTypeV3 defines the protocol problem-report message type.
	ProblemReportMsgTypeV3 = SpecV3 + "problem-report"
	// PresentationPreviewMsgTypeV3 defines the protocol presentation-preview inner object type.
	PresentationPreviewMsgTypeV3 = SpecV3 + "presentation-preview"
)

const (
	internalDataKey        = "internal_data_"
	transitionalPayloadKey = "transitionalPayload_%s"
)

type version string

const (
	version2 = version("present-proof V2")
	version3 = version("present-proof V3")
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
	StateName       string
	AckRequired     bool
	Direction       messageDirection
	ProtocolVersion version
	Properties      map[string]interface{}
}

type messageDirection string

const (
	inboundMessage  = messageDirection("InboundMessage")
	outboundMessage = messageDirection("OutboundMessage")
)

// metaData type to store data for internal usage.
type metaData struct {
	transitionalPayload
	state                 state
	presentationNames     []string
	properties            map[string]interface{}
	msgClone              service.DIDCommMsg
	presentation          *PresentationV2
	proposePresentation   *ProposePresentationV2
	request               *RequestPresentationV2
	presentationV3        *PresentationV3
	proposePresentationV3 *ProposePresentationV3
	requestV3             *RequestPresentationV3

	addProofFn func(presentation *verifiable.Presentation) error
	// err is used to determine whether callback was stopped
	// e.g the user received an action event and executes Stop(err) function
	// in that case `err` is equal to `err` which was passing to Stop function
	err error
}

func (md *metaData) Message() service.DIDCommMsg {
	return md.msgClone
}

func (md *metaData) Presentation() *PresentationV2 {
	return md.presentation
}

func (md *metaData) PresentationV3() *PresentationV3 {
	return md.presentationV3
}

func (md *metaData) ProposePresentation() *ProposePresentationV2 {
	return md.proposePresentation
}

func (md *metaData) ProposePresentationV3() *ProposePresentationV3 {
	return md.proposePresentationV3
}

func (md *metaData) RequestPresentation() *RequestPresentationV2 {
	return md.request
}

func (md *metaData) RequestPresentationV3() *RequestPresentationV3 {
	return md.requestV3
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

func (md *metaData) GetAddProofFn() func(presentation *verifiable.Presentation) error {
	return md.addProofFn
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
// USAGE: This message can be provided after receiving an Invitation message.
func WithPresentation(pp *PresentationParams) Opt {
	return func(md *metaData) {
		switch md.ProtocolVersion {
		default:
			fallthrough
		case version2:
			md.presentation = &PresentationV2{
				Type:                PresentationMsgTypeV2,
				Comment:             pp.Comment,
				Formats:             pp.Formats,
				PresentationsAttach: decorator.GenericAttachmentsToV1(pp.Attachments),
			}
		case version3:
			md.presentationV3 = &PresentationV3{
				Type: PresentationMsgTypeV3,
				Body: PresentationV3Body{
					GoalCode: pp.GoalCode,
					Comment:  pp.Comment,
				},
				Attachments: decorator.GenericAttachmentsToV2(pp.Attachments),
			}
		}
	}
}

// WithAddProofFn allows providing function that will sign the Presentation.
// USAGE: This fn can be provided after receiving a Invitation message.
func WithAddProofFn(addProof func(presentation *verifiable.Presentation) error) Opt {
	return func(md *metaData) {
		md.addProofFn = addProof
	}
}

// WithMultiOptions allows combining several options into one.
func WithMultiOptions(opts ...Opt) Opt {
	return func(md *metaData) {
		for _, opt := range opts {
			opt(md)
		}
	}
}

// WithProposePresentation allows providing ProposePresentation message
// USAGE: This message can be provided after receiving an Invitation message.
func WithProposePresentation(pp *ProposePresentationParams) Opt {
	return func(md *metaData) {
		switch md.ProtocolVersion {
		default:
			fallthrough
		case version2:
			md.proposePresentation = &ProposePresentationV2{
				Type:            ProposePresentationMsgTypeV2,
				Comment:         pp.Comment,
				Formats:         pp.Formats,
				ProposalsAttach: decorator.GenericAttachmentsToV1(pp.Attachments),
			}
		case version3:
			md.proposePresentationV3 = &ProposePresentationV3{
				Type: ProposePresentationMsgTypeV3,
				Body: ProposePresentationV3Body{
					GoalCode: pp.GoalCode,
					Comment:  pp.Comment,
				},
				Attachments: decorator.GenericAttachmentsToV2(pp.Attachments),
			}
		}
	}
}

// WithRequestPresentation allows providing RequestPresentation message
// USAGE: This message can be provided after receiving a propose message.
func WithRequestPresentation(msg *RequestPresentationParams) Opt {
	return func(md *metaData) {
		switch md.ProtocolVersion {
		default:
			fallthrough
		case version2:
			md.request = &RequestPresentationV2{
				ID:                         uuid.New().String(),
				Type:                       RequestPresentationMsgTypeV2,
				Comment:                    msg.Comment,
				WillConfirm:                msg.WillConfirm,
				Formats:                    msg.Formats,
				RequestPresentationsAttach: decorator.GenericAttachmentsToV1(msg.Attachments),
			}
		case version3:
			md.requestV3 = &RequestPresentationV3{
				ID:   uuid.New().String(),
				Type: RequestPresentationMsgTypeV3,
				Body: RequestPresentationV3Body{
					GoalCode:    msg.GoalCode,
					Comment:     msg.Comment,
					WillConfirm: msg.WillConfirm,
				},
				Attachments: decorator.GenericAttachmentsToV2(msg.Attachments),
			}
		}
	}
}

// WithFriendlyNames allows providing names for the presentations.
func WithFriendlyNames(names ...string) Opt {
	return func(md *metaData) {
		md.presentationNames = names
	}
}

// WithProperties allows providing custom properties.
func WithProperties(props map[string]interface{}) Opt {
	return func(md *metaData) {
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

// Service for the presentproof protocol.
type Service struct {
	service.Action
	service.Message
	store       storage.Store
	callbacks   chan *metaData
	messenger   service.Messenger
	middleware  Handler
	initialized bool
}

// New returns the presentproof service.
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
		return fmt.Errorf("failed to set store configuration: %w", err)
	}

	s.messenger = p.Messenger()
	s.store = store
	s.callbacks = make(chan *metaData)
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

// HandleInbound handles inbound message (presentproof protocol).
func (s *Service) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
	logger.Debugf("service.HandleInbound() input: msg=%+v myDID=%s theirDID=%s", msg, ctx.MyDID(), ctx.TheirDID())

	msgMap := msg.Clone()

	aEvent := s.ActionEvent()

	if aEvent == nil {
		// throw error if there is no action event registered for inbound messages
		return "", errors.New("no clients are registered to handle the message")
	}

	md, err := s.buildMetaData(msgMap, inboundMessage)
	if err != nil {
		return "", fmt.Errorf("buildMetaData: %w", err)
	}

	md.MyDID = ctx.MyDID()
	md.TheirDID = ctx.TheirDID()

	// trigger action event based on message type for inbound messages
	if canTriggerActionEvents(msgMap) {
		err = s.saveTransitionalPayload(md.PIID, &(md.transitionalPayload))
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
func (s *Service) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	logger.Debugf("service.HandleOutbound() input: msg=%+v myDID=%s theirDID=%s", msg, myDID, theirDID)

	msgMap := msg.Clone()

	md, err := s.buildMetaData(msgMap, outboundMessage)
	if err != nil {
		return "", fmt.Errorf("buildMetaData: %w", err)
	}

	md.MyDID = myDID
	md.TheirDID = theirDID

	thid, err := msgMap.ThreadID()
	if err != nil {
		return "", fmt.Errorf("failed to obtain the message's threadID : %w", err)
	}

	// if no action event is triggered, continue the execution
	return thid, s.handle(md)
}

func (s *Service) getCurrentInternalDataAndPIID(msg service.DIDCommMsgMap) (string, *internalData, error) {
	var protocolVersion version

	isV2, err := service.IsDIDCommV2(&msg)
	if err != nil {
		return "", nil, fmt.Errorf("checking message version: %w", err)
	}

	if isV2 {
		protocolVersion = version3
	} else {
		protocolVersion = version2
	}

	piID, err := getPIID(msg)
	if errors.Is(err, service.ErrThreadIDNotFound) {
		msg.SetID(uuid.New().String(), service.WithVersion(getDIDVersion(getVersion(msg.Type()))))

		return msg.ID(), &internalData{StateName: stateNameStart, ProtocolVersion: protocolVersion}, nil
	}

	if err != nil {
		return "", nil, fmt.Errorf("piID: %w", err)
	}

	data, err := s.currentInternalData(piID, protocolVersion)
	if err != nil {
		return "", nil, fmt.Errorf("current internal data: %w", err)
	}

	return piID, data, nil
}

func (s *Service) buildMetaData(msg service.DIDCommMsgMap, direction messageDirection) (*metaData, error) {
	piID, data, err := s.getCurrentInternalDataAndPIID(msg)
	if err != nil {
		return nil, fmt.Errorf("current internal data and PIID: %w", err)
	}

	current := stateFromName(data.StateName, getVersion(msg.Type()))

	next, err := nextState(msg, direction)
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
			Direction:       direction,
			ProtocolVersion: data.ProtocolVersion,
			Properties:      next.Properties(),
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

		logger.Errorf("failed to handle msgID=%s : %s", msg.Msg.ID(), msg.err)

		msg.state = &abandoned{V: getVersion(msg.Msg.Type()), Code: codeInternalError}

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
	current := md.state

	for !isNoOp(current) {
		next, action, err := s.execute(current, md)
		if err != nil {
			return fmt.Errorf("execute: %w", err)
		}

		if !isNoOp(next) && !current.CanTransitionTo(next) {
			return fmt.Errorf("invalid state transition: %s --> %s", current.Name(), next.Name())
		}

		// WARN: md.ackRequired is being modified by requestSent state
		data := &internalData{
			StateName:       current.Name(),
			AckRequired:     md.AckRequired,
			ProtocolVersion: md.ProtocolVersion,
		}

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
	AckRequired     bool
	StateName       string
	ProtocolVersion version
}

func (s *Service) saveInternalData(piID string, data *internalData) error {
	src, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return s.store.Put(internalDataKey+piID, src)
}

func (s *Service) currentInternalData(piID string, protocolVersion version) (*internalData, error) {
	src, err := s.store.Get(internalDataKey + piID)
	if errors.Is(err, storage.ErrDataNotFound) {
		return &internalData{StateName: stateNameStart, ProtocolVersion: protocolVersion}, nil
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

// stateFromName returns the state by given name.
func stateFromName(name, v string) state {
	switch name {
	case stateNameStart:
		return &start{}
	case StateNameAbandoned:
		return &abandoned{V: v}
	case StateNameDone:
		return &done{V: v}
	case stateNameRequestSent:
		return &requestSent{V: v}
	case stateNamePresentationReceived:
		return &presentationReceived{V: v}
	case stateNameProposalReceived:
		return &proposalReceived{V: v}
	case stateNameRequestReceived:
		return &requestReceived{V: v}
	case stateNamePresentationSent:
		return &presentationSent{V: v}
	case stateNameProposalSent:
		return &proposalSent{V: v}
	default:
		return &noOp{}
	}
}

func nextState(msg service.DIDCommMsgMap, direction messageDirection) (state, error) {
	switch msg.Type() {
	case RequestPresentationMsgTypeV2, RequestPresentationMsgTypeV3:
		switch direction {
		case inboundMessage:
			return &requestReceived{V: getVersion(msg.Type())}, nil
		case outboundMessage:
			return &requestSent{V: getVersion(msg.Type())}, nil
		}
	case ProposePresentationMsgTypeV2, ProposePresentationMsgTypeV3:
		switch direction {
		case inboundMessage:
			return &proposalReceived{V: getVersion(msg.Type())}, nil
		case outboundMessage:
			return &proposalSent{V: getVersion(msg.Type())}, nil
		}
	case PresentationMsgTypeV2, PresentationMsgTypeV3:
		return &presentationReceived{V: getVersion(msg.Type())}, nil
	case ProblemReportMsgTypeV2, ProblemReportMsgTypeV3:
		return &abandoned{V: getVersion(msg.Type()), properties: redirectInfo(msg)}, nil
	case AckMsgTypeV2, AckMsgTypeV3:
		return &done{V: getVersion(msg.Type()), properties: redirectInfo(msg)}, nil
	}

	return nil, fmt.Errorf("unrecognized msgType: %s", msg.Type())
}

func getVersion(t string) string {
	if strings.HasPrefix(t, SpecV2) {
		return SpecV2
	}

	return SpecV3
}

func redirectInfo(msg service.DIDCommMsgMap) map[string]interface{} {
	if redirectInfo, ok := msg[webRedirect].(map[string]interface{}); ok {
		return redirectInfo
	}

	return map[string]interface{}{}
}

func getDIDVersion(v string) service.Version {
	if v == SpecV3 {
		return service.V2
	}

	return service.V1
}

func (s *Service) saveTransitionalPayload(id string, data *transitionalPayload) error {
	src, err := json.Marshal(*data)
	if err != nil {
		return fmt.Errorf("marshal transitional payload: %w", err)
	}

	return s.store.Put(fmt.Sprintf(transitionalPayloadKey, id), src, storage.Tag{Name: transitionalPayloadKey})
}

// canTriggerActionEvents checks if the incoming message can trigger an action event.
func canTriggerActionEvents(msg service.DIDCommMsg) bool {
	return msg.Type() == PresentationMsgTypeV2 ||
		msg.Type() == ProposePresentationMsgTypeV2 ||
		msg.Type() == RequestPresentationMsgTypeV2 ||
		msg.Type() == ProblemReportMsgTypeV2 ||
		msg.Type() == PresentationMsgTypeV3 ||
		msg.Type() == ProposePresentationMsgTypeV3 ||
		msg.Type() == RequestPresentationMsgTypeV3 ||
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

// Actions returns actions for the async usage.
func (s *Service) Actions() ([]Action, error) {
	records, err := s.store.Query(transitionalPayloadKey)
	if err != nil {
		return nil, fmt.Errorf("failed to query store: %w", err)
	}

	defer storage.Close(records, logger)

	var actions []Action

	more, err := records.Next()
	if err != nil {
		return nil, fmt.Errorf("failed to get next set of data from records: %w", err)
	}

	for more {
		value, err := records.Value()
		if err != nil {
			return nil, fmt.Errorf("failed to get value from records: %w", err)
		}

		var action Action
		if errUnmarshal := json.Unmarshal(value, &action); errUnmarshal != nil {
			return nil, fmt.Errorf("unmarshal: %w", errUnmarshal)
		}

		actions = append(actions, action)

		more, err = records.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to get next set of data from records: %w", err)
		}
	}

	return actions, nil
}

// ActionContinue allows proceeding with the action by the piID.
func (s *Service) ActionContinue(piID string, opts ...Opt) error {
	tPayload, err := s.getTransitionalPayload(piID)
	if err != nil {
		return fmt.Errorf("get transitional payload: %w", err)
	}

	md := &metaData{
		transitionalPayload: *tPayload,
		state:               stateFromName(tPayload.StateName, getVersion(tPayload.Msg.Type())),
		msgClone:            tPayload.Msg.Clone(),
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

	md := &metaData{
		transitionalPayload: *tPayload,
		state:               stateFromName(tPayload.StateName, tPayload.Msg.Type()),
		msgClone:            tPayload.Msg.Clone(),
		properties:          tPayload.Properties,
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
	case ProposePresentationMsgTypeV2, RequestPresentationMsgTypeV2,
		PresentationMsgTypeV2, AckMsgTypeV2, ProblemReportMsgTypeV2,
		ProposePresentationMsgTypeV3, RequestPresentationMsgTypeV3,
		PresentationMsgTypeV3, AckMsgTypeV3, ProblemReportMsgTypeV3:
		return true
	}

	return false
}
