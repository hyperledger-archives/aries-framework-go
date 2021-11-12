/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofbandv2

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// Name of this protocol service.
	Name = "out-of-band/2.0"
	// PIURI is the Out-of-Band protocol's protocol instance URI.
	PIURI = "https://didcomm.org/" + Name
	// InvitationMsgType is the '@type' for the invitation message.
	InvitationMsgType = PIURI + "/invitation"

	// TODO channel size - https://github.com/hyperledger/aries-framework-go/issues/246
	callbackChannelSize = 10

	contextKey = "context_%s"
)

var logger = log.New(fmt.Sprintf("aries-framework/%s/service", Name))

// Options is a container for optional values provided by the user.
type Options interface {
	// MyLabel is the label to share with the other agent in the subsequent protocol calls.
	MyLabel() string
}

// Service implements the Out-Of-Band V2 protocol.
type Service struct {
	service.Action
	service.Message
	callbackChannel        chan *callback
	transientStore         storage.Store
	inboundHandler         func() service.InboundHandler
	listenerFunc           func()
	messenger              service.Messenger
	myMediaTypeProfiles    []string
	msgTypeServicesTargets map[string]string
	allServices            []dispatcher.ProtocolService
}

type callback struct {
	msg      service.DIDCommMsg
	myDID    string
	theirDID string
	ctx      *context
}

type attachmentHandlingState struct {
	// ID becomes the parent thread ID of subsequent protocol call
	ID         string
	Invitation *Invitation
	Done       bool
}

// Action contains helpful information about action.
type Action struct {
	// Protocol instance ID
	PIID         string
	Msg          service.DIDCommMsgMap
	ProtocolName string
	MyDID        string
	TheirDID     string
}

// context keeps payload needed for Continue function to proceed with the action.
type context struct {
	Action
	CurrentStateName  string
	Inbound           bool
	Invitation        *Invitation
	MyLabel           string
	RouterConnections []string
}

// Provider provides this service's dependencies.
type Provider interface {
	Service(id string) (interface{}, error)
	StorageProvider() storage.Provider
	ProtocolStateStorageProvider() storage.Provider
	InboundDIDCommMessageHandler() func() service.InboundHandler
	Messenger() service.Messenger
	MediaTypeProfiles() []string
	ServiceMsgTypeTargets() []dispatcher.MessageTypeTarget
	AllServices() []dispatcher.ProtocolService
}

// New creates a new instance of the out-of-band service.
func New(p Provider) (*Service, error) {
	store, err := p.ProtocolStateStorageProvider().OpenStore(Name)
	if err != nil {
		return nil, fmt.Errorf("oob/2.0 failed to open the transientStore : %w", err)
	}

	err = p.ProtocolStateStorageProvider().SetStoreConfig(Name,
		storage.StoreConfiguration{TagNames: []string{contextKey}})
	if err != nil {
		return nil, fmt.Errorf("oob/2.0 failed to set transientStore config in protocol state transientStore: %w", err)
	}

	msgTypeServicesTargets := map[string]string{}

	for _, v := range p.ServiceMsgTypeTargets() {
		msgTypeServicesTargets[v.Target] = v.MsgType
	}

	s := &Service{
		callbackChannel:        make(chan *callback, callbackChannelSize),
		transientStore:         store,
		inboundHandler:         p.InboundDIDCommMessageHandler(),
		messenger:              p.Messenger(),
		myMediaTypeProfiles:    p.MediaTypeProfiles(),
		msgTypeServicesTargets: msgTypeServicesTargets,
		allServices:            p.AllServices(),
	}

	s.listenerFunc = listener(s.callbackChannel, s.handleCallback)

	go s.listenerFunc()

	return s, nil
}

// Name is this service's name.
func (s *Service) Name() string {
	return Name
}

// Accept determines whether this service can handle the given type of message.
func (s *Service) Accept(msgType string) bool {
	return msgType == InvitationMsgType
}

// HandleInbound handles inbound messages.
func (s *Service) HandleInbound(msg service.DIDCommMsg, didCommCtx service.DIDCommContext) (string, error) {
	logger.Debugf("oob/2.0 inbound message: %s", msg)

	if msg == nil {
		return "", fmt.Errorf("oob/2.0 cannot handle nil inbound message")
	}

	if !s.Accept(msg.Type()) {
		return "", fmt.Errorf("oob/2.0 unsupported message type %s", msg.Type())
	}

	events := s.ActionEvent()
	if events == nil {
		return "", fmt.Errorf("oob/2.0 no clients registered to handle action events for %s protocol", Name)
	}

	myContext, err := s.currentContext(msg, didCommCtx, nil)
	if err != nil {
		return "", fmt.Errorf("oob/2.0 unable to load current context for msgID=%s: %w", msg.ID(), err)
	}

	if requiresApproval(msg) {
		go func() {
			s.requestApproval(myContext, events, msg)
		}()

		return "", nil
	}

	return "", s.handleContext(myContext)
}

func (s *Service) handleContext(ctx *context) error {
	logger.Debugf("oob/2.0 context: %+v", ctx)

	current, err := stateFromName(ctx.CurrentStateName)
	if err != nil {
		return fmt.Errorf("oob/2.0 unable to instantiate current state: %w", err)
	}

	deps := &dependencies{
		saveAttchStateFunc:    s.save,
		dispatchAttachmntFunc: s.setInvitationAsDone,
	}

	var (
		stop   bool
		next   state
		finish finisher
	)

	for !stop {
		logger.Debugf("oob/2.0 start executing state %s", current.Name())

		msgCopy := ctx.Msg.Clone()

		go sendMsgEvent(service.PreState, current.Name(), &s.Message, msgCopy, &eventProps{})

		sendPostStateMsg := func(props *eventProps) {
			go sendMsgEvent(service.PostState, current.Name(), &s.Message, msgCopy, props)
		}

		next, finish, stop, err = current.Execute(ctx, deps)
		if err != nil {
			sendPostStateMsg(&eventProps{Err: err})

			return fmt.Errorf("oob/2.0 failed to execute state %s: %w", current.Name(), err)
		}

		logger.Debugf("oob/2.0 completed %s.Execute()", current.Name())

		ctx.CurrentStateName = next.Name()

		err = s.updateContext(ctx, next, sendPostStateMsg)
		if err != nil {
			return fmt.Errorf("oob/2.0 failed to update context: %w", err)
		}

		err = finish(s.messenger)
		if err != nil {
			sendPostStateMsg(&eventProps{Err: err})

			return fmt.Errorf("oob/2.0 failed to execute finisher for state %s: %w", current.Name(), err)
		}

		sendPostStateMsg(&eventProps{})

		logger.Debugf("oob/2.0 end executing state %s", current.Name())

		current = next
	}

	return nil
}

func (s *Service) updateContext(ctx *context, next state, sendPostStateMsg func(*eventProps)) error {
	if isTheEnd(next) {
		err := s.deleteContext(ctx.PIID)
		if err != nil {
			sendPostStateMsg(&eventProps{Err: err})

			return fmt.Errorf("oob/2.0 failed to delete context: %w", err)
		}

		logger.Debugf("oob/2.0 deleted context: %+v", ctx)

		return nil
	}

	err := s.saveContext(ctx.PIID, ctx)
	if err != nil {
		sendPostStateMsg(&eventProps{Err: err})

		return fmt.Errorf("oob/2.0 failed to update context: %w", err)
	}

	logger.Debugf("oob/2.0 updated context: %+v", ctx)

	return nil
}

func (s *Service) requestApproval(ctx *context, events chan<- service.DIDCommAction, msg service.DIDCommMsg) {
	event := service.DIDCommAction{
		ProtocolName: Name,
		Message:      msg,
		Continue: func(args interface{}) {
			var opts Options

			switch t := args.(type) {
			case Options:
				opts = t
			default:
				opts = &userOptions{}
			}

			ctx.MyLabel = opts.MyLabel()

			s.callbackChannel <- &callback{
				msg:      msg,
				myDID:    ctx.MyDID,
				theirDID: ctx.TheirDID,
				ctx:      ctx,
			}

			logger.Debugf("oob/2.0 continued with options: %+v", opts)
		},
		Stop: func(er error) {
			logger.Infof("oob/2.0 user requested protocol to stop: %s", er)

			if err := s.deleteContext(ctx.PIID); err != nil {
				logger.Errorf("oob/2.0 delete context: %s", err)
			}
		},
	}

	events <- event

	logger.Debugf("oob/2.0 dispatched event: %+v", event)
}

func (s *Service) saveContext(id string, data *context) error {
	src, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("oob/2.0 marshal transitional payload: %w", err)
	}

	return s.transientStore.Put(fmt.Sprintf(contextKey, id), src, storage.Tag{Name: contextKey})
}

func (s *Service) deleteContext(id string) error {
	return s.transientStore.Delete(fmt.Sprintf(contextKey, id))
}

func sendMsgEvent(
	t service.StateMsgType, stateID string, l *service.Message, msg service.DIDCommMsg, p service.EventProperties) {
	stateMsg := service.StateMsg{
		ProtocolName: Name,
		Type:         t,
		StateID:      stateID,
		Msg:          msg,
		Properties:   p,
	}

	logger.Debugf("oob/2.0 sending state msg: %+v\n", stateMsg)

	for _, handler := range l.MsgEvents() {
		handler <- stateMsg
	}
}

// HandleOutbound handles outbound messages.
func (s *Service) HandleOutbound(_ service.DIDCommMsg, _, _ string) (string, error) {
	// TODO implement
	return "", errors.New("oob/2.0 not implemented")
}

func (s *Service) currentContext(msg service.DIDCommMsg, ctx service.DIDCommContext, opts Options) (*context, error) {
	if msg.Type() == InvitationMsgType {
		myContext := &context{
			Action: Action{
				PIID:         msg.ID(),
				ProtocolName: Name,
				Msg:          msg.Clone(),
				MyDID:        ctx.MyDID(),
				TheirDID:     ctx.TheirDID(),
			},
			Inbound: true,
		}

		myContext.CurrentStateName = StateNameInitial

		if opts != nil {
			myContext.MyLabel = opts.MyLabel()
		}

		return myContext, s.saveContext(msg.ID(), myContext)
	}

	return nil, fmt.Errorf("invalid message type %v", msg.Type())
}

// AcceptInvitation from another agent.
func (s *Service) AcceptInvitation(i *Invitation, options Options) error {
	msg := service.NewDIDCommMsgMap(i)

	err := validateInvitationAcceptance(msg, s.myMediaTypeProfiles)
	if err != nil {
		return fmt.Errorf("oob/2.0 unable to accept invitation: %w", err)
	}

	clbk := &callback{
		msg: msg,
	}

	clbk.ctx, err = s.currentContext(msg, service.EmptyDIDCommContext(), options)
	if err != nil {
		return fmt.Errorf("oob/2.0 failed to create context for invitation: %w", err)
	}

	err = s.handleCallback(clbk)
	if err != nil {
		return fmt.Errorf("oob/2.0 failed to accept invitation : %w", err)
	}

	if i.Body != nil && i.Body.GoalCode != "" {
		serviceURL := s.msgTypeServicesTargets[i.Body.GoalCode]
		for _, srvc := range s.allServices {
			if strings.Contains(serviceURL, srvc.Name()) {
				isHandled := handleInboundService(serviceURL, srvc, i.Requests)

				if isHandled {
					logger.Debugf("oob/2.0 matching target service found for url '%v' and executed, "+
						"oobv2.AcceptInvitation() is done.", serviceURL)
					return nil
				}
			}
		}

		logger.Debugf("oob/2.0 no matching target service found for url '%v', oobv2.AcceptInvitation() is done but"+
			" no target service triggered", serviceURL)
	}

	logger.Debugf("oob/2.0 request body or Goal code is empty, oobv2.AcceptInvitation() is done but no" +
		"target service triggered")

	return nil
}

func handleInboundService(serviceURL string, srvc dispatcher.ProtocolService,
	attachments []*decorator.AttachmentV2) bool {
	for _, atchmnt := range attachments {
		serviceRequest, err := atchmnt.Data.Fetch()
		if err != nil {
			logger.Debugf("oob/2.0 fetching target service '%v' for url '%v' attachment request failed:"+
				" %v, skipping attachment entry..", srvc.Name(), serviceURL, err)

			continue
		}

		didCommMsgRequest := service.DIDCommMsgMap{}

		err = didCommMsgRequest.UnmarshalJSON(serviceRequest)
		if err != nil {
			logger.Debugf("oob/2.0 fetching target service '%v' for url '%v' attachment request failed:"+
				" %v, skipping attachment entry..", srvc.Name(), serviceURL, err)

			continue
		}

		id, err := srvc.HandleInbound(didCommMsgRequest, service.EmptyDIDCommContext())
		if err != nil {
			logger.Debugf("oob/2.0 executing target service '%v' for url '%v' failed: %v, skipping "+
				"attachment entry..", srvc.Name(), serviceURL, err)

			continue
		}

		logger.Debugf("oob/2.0 successfully executed target service '%v' for target url: '%v', returned id: %v",
			srvc.Name(), serviceURL, id)

		return true
	}

	return false
}

func listener(
	callbacks chan *callback,
	handleCallbackFunc func(*callback) error) func() {
	return func() {
		for c := range callbacks {
			switch c.msg.Type() {
			case InvitationMsgType:
				err := handleCallbackFunc(c)
				if err != nil {
					logutil.LogError(logger, Name, "handleCallback", err.Error(),
						logutil.CreateKeyValueString("msgType", c.msg.Type()),
						logutil.CreateKeyValueString("msgID", c.msg.ID()))

					continue
				}
			default:
				logutil.LogError(logger, Name, "callbackChannel", "oob/2.0 unsupported msg type",
					logutil.CreateKeyValueString("msgType", c.msg.Type()),
					logutil.CreateKeyValueString("msgID", c.msg.ID()))
			}
		}
	}
}

func (s *Service) handleCallback(c *callback) error {
	switch c.msg.Type() {
	case InvitationMsgType:
		return s.handleInvitationCallback(c)
	default:
		return fmt.Errorf("unsupported message type: %s", c.msg.Type())
	}
}

func (s *Service) handleInvitationCallback(c *callback) error {
	logger.Debugf("oob/2.0 input: %+v", c)
	logger.Debugf("oob/2.0 context: %+v", c.ctx)

	err := validateInvitationAcceptance(c.msg, s.myMediaTypeProfiles)
	if err != nil {
		return fmt.Errorf("unable to handle invitation: %w", err)
	}

	err = s.handleContext(c.ctx)
	if err != nil {
		return fmt.Errorf("failed to handle invitation: %w", err)
	}

	return nil
}

func (s *Service) setInvitationAsDone(invID string) error {
	state, err := s.fetchAttachmentHandlingState(invID)
	if err != nil {
		return fmt.Errorf("failed to load attachment handling state : %w", err)
	}

	state.Done = true

	// Save state as Done before dispatching message because the out-of-band protocol
	// has done its job in getting this far. The other protocol maintains its own state.
	err = s.save(state)
	if err != nil {
		return fmt.Errorf("failed to update state : %w", err)
	}

	return nil
}

func (s *Service) save(state *attachmentHandlingState) error {
	bytes, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to save state=%+v : %w", state, err)
	}

	err = s.transientStore.Put(state.ID, bytes)
	if err != nil {
		return fmt.Errorf("failed to save state : %w", err)
	}

	return nil
}

func (s *Service) fetchAttachmentHandlingState(id string) (*attachmentHandlingState, error) {
	bytes, err := s.transientStore.Get(id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch attachment handling state using id=%s : %w", id, err)
	}

	state := &attachmentHandlingState{}

	err = json.Unmarshal(bytes, state)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal state %+v : %w", state, err)
	}

	return state, nil
}

func validateInvitationAcceptance(msg service.DIDCommMsg, myProfiles []string) error {
	if msg.Type() != InvitationMsgType {
		return nil
	}

	inv := &Invitation{}

	err := msg.Decode(inv)
	if err != nil {
		return fmt.Errorf("validateInvitationAcceptance: failed to decode invitation: %w", err)
	}

	if !matchMediaTypeProfiles(inv.Body.Accept, myProfiles) {
		return fmt.Errorf("no acceptable media type profile found in invitation, invitation Accept property: [%v], "+
			"agent mediatypeprofiles: [%v]", inv.Body.Accept, myProfiles)
	}

	return nil
}

func matchMediaTypeProfiles(theirProfiles, myProfiles []string) bool {
	if theirProfiles == nil {
		// we use our preferred media type profile instead of confirming an overlap exists
		return true
	}

	if myProfiles == nil {
		myProfiles = transport.MediaTypeProfiles()
	}

	profiles := list2set(myProfiles)

	for _, a := range theirProfiles {
		if _, valid := profiles[a]; valid {
			return true
		}
	}

	return false
}

func list2set(list []string) map[string]struct{} {
	set := map[string]struct{}{}

	for _, e := range list {
		set[e] = struct{}{}
	}

	return set
}

func isTheEnd(s state) bool {
	_, ok := s.(*stateDone)

	return ok
}

type eventProps struct {
	Err error `json:"err"`
}

func (e *eventProps) Error() error {
	return e.Err
}

type userOptions struct {
	myLabel string
}

func (e *userOptions) MyLabel() string {
	return e.myLabel
}

// All implements EventProperties interface.
func (e *eventProps) All() map[string]interface{} {
	return map[string]interface{}{
		"error": e.Error(),
	}
}
