/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	didcommModel "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// Name of this protocol service.
	Name = "out-of-band"
	// PIURI is the Out-of-Band protocol's protocol instance URI.
	PIURI = "https://didcomm.org/out-of-band/1.0"
	// oldPIURI is the old OOB protocol's protocol instance URI.
	oldPIURI = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/out-of-band/1.0"
	// InvitationMsgType is the '@type' for the invitation message.
	InvitationMsgType = PIURI + "/invitation"
	// OldInvitationMsgType is the `@type` for the old invitation message.
	OldInvitationMsgType = oldPIURI + "/invitation"
	// HandshakeReuseMsgType is the '@type' for the reuse message.
	HandshakeReuseMsgType = PIURI + "/handshake-reuse"
	// HandshakeReuseAcceptedMsgType is the '@type' for the reuse-accepted message.
	HandshakeReuseAcceptedMsgType = PIURI + "/handshake-reuse-accepted"

	// TODO channel size - https://github.com/hyperledger/aries-framework-go/issues/246
	callbackChannelSize = 10

	contextKey = "context_%s"
)

var logger = log.New(fmt.Sprintf("aries-framework/%s/service", Name))

var errIgnoredDidEvent = errors.New("ignored")

// Options is a container for optional values provided by the user.
type Options interface {
	// MyLabel is the label to share with the other agent in the subsequent did-exchange.
	MyLabel() string
	RouterConnections() []string
	ReuseAnyConnection() bool
	ReuseConnection() string
}

type didExchSvc interface {
	RespondTo(*didexchange.OOBInvitation, []string) (string, error)
	SaveInvitation(invitation *didexchange.OOBInvitation) error
}

type connectionRecorder interface {
	SaveInvitation(string, interface{}) error
	GetConnectionRecord(string) (*connection.Record, error)
	GetConnectionIDByDIDs(string, string) (string, error)
	QueryConnectionRecords() ([]*connection.Record, error)
}

// Service implements the Out-Of-Band protocol.
type Service struct {
	service.Action
	service.Message
	callbackChannel            chan *callback
	didSvc                     didExchSvc
	didEvents                  chan service.StateMsg
	transientStore             storage.Store
	connections                connectionRecorder
	inboundHandler             func() service.InboundHandler
	chooseAttachmentFunc       func(*attachmentHandlingState) (*decorator.Attachment, error)
	extractDIDCommMsgBytesFunc func(*decorator.Attachment) ([]byte, error)
	listenerFunc               func()
	messenger                  service.Messenger
	myMediaTypeProfiles        []string
	initialized                bool
}

type callback struct {
	msg      service.DIDCommMsg
	myDID    string
	theirDID string
	ctx      *context
}

type attachmentHandlingState struct {
	// ID becomes the parent thread ID of didexchange
	ID           string
	ConnectionID string
	Invitation   *Invitation
	Done         bool
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
	CurrentStateName   string
	Inbound            bool
	ReuseAnyConnection bool
	ReuseConnection    string
	ConnectionID       string
	Invitation         *Invitation
	DIDExchangeInv     *didexchange.OOBInvitation
	MyLabel            string
	RouterConnections  []string
}

// Provider provides this service's dependencies.
type Provider interface {
	Service(id string) (interface{}, error)
	StorageProvider() storage.Provider
	ProtocolStateStorageProvider() storage.Provider
	InboundDIDCommMessageHandler() func() service.InboundHandler
	Messenger() service.Messenger
	MediaTypeProfiles() []string
}

// New creates a new instance of the out-of-band service.
func New(p Provider) (*Service, error) {
	svc := Service{}

	err := svc.Initialize(p)
	if err != nil {
		return nil, err
	}

	return &svc, nil
}

// Initialize initializes the Service. If Initialize succeeds, any further call is a no-op.
func (s *Service) Initialize(prov interface{}) error { // nolint:funlen
	if s.initialized {
		return nil
	}

	p, ok := prov.(Provider)
	if !ok {
		return fmt.Errorf("expected provider of type `%T`, got type `%T`", Provider(nil), p)
	}

	svc, err := p.Service(didexchange.DIDExchange)
	if err != nil {
		return fmt.Errorf("failed to initialize outofband service : %w", err)
	}

	didSvc, ok := svc.(didExchSvc)
	if !ok {
		return errors.New("failed to cast the didexchange service to satisfy our dependency")
	}

	store, err := p.ProtocolStateStorageProvider().OpenStore(Name)
	if err != nil {
		return fmt.Errorf("failed to open the transientStore : %w", err)
	}

	err = p.ProtocolStateStorageProvider().SetStoreConfig(Name,
		storage.StoreConfiguration{TagNames: []string{contextKey}})
	if err != nil {
		return fmt.Errorf("failed to set transientStore config in protocol state transientStore: %w", err)
	}

	connectionRecorder, err := connection.NewRecorder(p)
	if err != nil {
		return fmt.Errorf("failed to open a connection.Lookup : %w", err)
	}

	s.callbackChannel = make(chan *callback, callbackChannelSize)
	s.didSvc = didSvc
	s.didEvents = make(chan service.StateMsg, callbackChannelSize)
	s.transientStore = store
	s.connections = connectionRecorder
	s.inboundHandler = p.InboundDIDCommMessageHandler()
	s.chooseAttachmentFunc = chooseAttachment
	s.extractDIDCommMsgBytesFunc = extractDIDCommMsgBytes
	s.messenger = p.Messenger()
	s.myMediaTypeProfiles = p.MediaTypeProfiles()

	s.listenerFunc = listener(s.callbackChannel, s.didEvents, s.handleCallback, s.handleDIDEvent)

	didEventsSvc, ok := didSvc.(service.Event)
	if !ok {
		return errors.New("failed to cast didexchange service to service.Event")
	}

	if err = didEventsSvc.RegisterMsgEvent(s.didEvents); err != nil {
		return fmt.Errorf("failed to register for didexchange protocol msgs : %w", err)
	}

	go s.listenerFunc()

	s.initialized = true

	return nil
}

// Name is this service's name.
func (s *Service) Name() string {
	return Name
}

// Accept determines whether this service can handle the given type of message.
func (s *Service) Accept(msgType string) bool {
	switch msgType {
	case InvitationMsgType, HandshakeReuseMsgType, HandshakeReuseAcceptedMsgType, OldInvitationMsgType:
		return true
	}

	return false
}

// HandleInbound handles inbound messages.
func (s *Service) HandleInbound(msg service.DIDCommMsg, didCommCtx service.DIDCommContext) (string, error) {
	logger.Debugf("inbound message: %s", msg)

	if !s.Accept(msg.Type()) {
		return "", fmt.Errorf("unsupported message type %s", msg.Type())
	}

	events := s.ActionEvent()
	if events == nil {
		return "", fmt.Errorf("no clients registered to handle action events for %s protocol", Name)
	}

	myContext, err := s.currentContext(msg, didCommCtx, nil)
	if err != nil {
		return "", fmt.Errorf("unable to load current context for msgID=%s: %w", msg.ID(), err)
	}

	if requiresApproval(msg) {
		go func() {
			s.requestApproval(myContext, events, msg)
		}()

		return "", nil
	}

	return "", s.handleContext(myContext)
}

func (s *Service) handleContext(ctx *context) error { // nolint:funlen
	logger.Debugf("context: %+v", ctx)

	current, err := stateFromName(ctx.CurrentStateName)
	if err != nil {
		return fmt.Errorf("unable to instantiate current state: %w", err)
	}

	deps := &dependencies{
		connections:           s.connections,
		didSvc:                s.didSvc,
		saveAttchStateFunc:    s.save,
		dispatchAttachmntFunc: s.dispatchInvitationAttachment,
	}

	var (
		stop   bool
		next   state
		finish finisher
	)

	for !stop {
		logger.Debugf("start executing state %s", current.Name())

		msgCopy := ctx.Msg.Clone()

		go sendMsgEvent(service.PreState, current.Name(), &s.Message, msgCopy, &eventProps{ConnID: ctx.ConnectionID})

		sendPostStateMsg := func(props *eventProps) {
			go sendMsgEvent(service.PostState, current.Name(), &s.Message, msgCopy, props)
		}

		next, finish, stop, err = current.Execute(ctx, deps)
		if err != nil {
			sendPostStateMsg(&eventProps{Err: err})

			return fmt.Errorf("failed to execute state %s: %w", current.Name(), err)
		}

		logger.Debugf("completed %s.Execute()", current.Name())

		ctx.CurrentStateName = next.Name()

		err = s.updateContext(ctx, next, sendPostStateMsg)
		if err != nil {
			return fmt.Errorf("failed to update context: %w", err)
		}

		err = finish(s.messenger)
		if err != nil {
			sendPostStateMsg(&eventProps{Err: err})

			return fmt.Errorf("failed to execute finisher for state %s: %w", current.Name(), err)
		}

		sendPostStateMsg(&eventProps{ConnID: ctx.ConnectionID})

		logger.Debugf("end executing state %s", current.Name())

		current = next
	}

	return nil
}

func (s *Service) updateContext(ctx *context, next state, sendPostStateMsg func(*eventProps)) error {
	if isTheEnd(next) {
		err := s.deleteContext(ctx.PIID)
		if err != nil {
			sendPostStateMsg(&eventProps{Err: err})

			return fmt.Errorf("failed to delete context: %w", err)
		}

		logger.Debugf("deleted context: %+v", ctx)

		return nil
	}

	err := s.saveContext(ctx.PIID, ctx)
	if err != nil {
		sendPostStateMsg(&eventProps{Err: err})

		return fmt.Errorf("failed to update context: %w", err)
	}

	logger.Debugf("updated context: %+v", ctx)

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

			ctx.ReuseConnection = opts.ReuseConnection()
			ctx.ReuseAnyConnection = opts.ReuseAnyConnection()
			ctx.RouterConnections = opts.RouterConnections()
			ctx.MyLabel = opts.MyLabel()

			s.callbackChannel <- &callback{
				msg:      msg,
				myDID:    ctx.MyDID,
				theirDID: ctx.TheirDID,
				ctx:      ctx,
			}

			logger.Debugf("continued with options: %+v", opts)
		},
		Stop: func(er error) {
			logger.Infof("user requested protocol to stop: %s", er)

			if err := s.deleteContext(ctx.PIID); err != nil {
				logger.Errorf("delete context: %s", err)
			}
		},
	}

	events <- event

	logger.Debugf("dispatched event: %+v", event)
}

// Actions returns actions for the async usage.
func (s *Service) Actions() ([]Action, error) {
	records, err := s.transientStore.Query(contextKey)
	if err != nil {
		return nil, fmt.Errorf("failed to query transientStore: %w", err)
	}

	defer storage.Close(records, logger)

	var actions []Action

	more, err := records.Next()
	if err != nil {
		return nil, fmt.Errorf("failed to get next set of data from records: %w", err)
	}

	for more {
		value, errValue := records.Value()
		if errValue != nil {
			return nil, fmt.Errorf("failed to get value from records: %w", errValue)
		}

		var action Action
		if errUnmarshal := json.Unmarshal(value, &action); errUnmarshal != nil {
			return nil, fmt.Errorf("unmarshal: %w", errUnmarshal)
		}

		actions = append(actions, action)

		var errNext error

		more, errNext = records.Next()
		if errNext != nil {
			return nil, fmt.Errorf("failed to get next set of data from records: %w", errNext)
		}
	}

	return actions, nil
}

// ActionContinue allows proceeding with the action by the piID.
func (s *Service) ActionContinue(piID string, opts Options) error {
	ctx, err := s.loadContext(piID)
	if err != nil {
		return fmt.Errorf("load context: %w", err)
	}

	ctx.RouterConnections = opts.RouterConnections()
	ctx.ReuseConnection = opts.ReuseConnection()
	ctx.ReuseAnyConnection = opts.ReuseAnyConnection()
	ctx.MyLabel = opts.MyLabel()

	err = validateInvitationAcceptance(ctx.Msg, s.myMediaTypeProfiles, opts)
	if err != nil {
		return fmt.Errorf("unable to accept invitation: %w", err)
	}

	go func() {
		s.callbackChannel <- &callback{
			msg:      ctx.Msg,
			myDID:    ctx.MyDID,
			theirDID: ctx.TheirDID,
			ctx:      ctx,
		}
	}()

	return nil
}

// ActionStop allows stopping the action by the piID.
func (s *Service) ActionStop(piID string, _ error) error {
	logger.Infof("user requested action to stop: piid=%s", piID)

	ctx, err := s.loadContext(piID)
	if err != nil {
		return fmt.Errorf("get context: %w", err)
	}

	return s.deleteContext(ctx.PIID)
}

func (s *Service) loadContext(id string) (*context, error) {
	src, err := s.transientStore.Get(fmt.Sprintf(contextKey, id))
	if err != nil {
		return nil, fmt.Errorf("transientStore get: %w", err)
	}

	t := &context{}
	if err := json.Unmarshal(src, t); err != nil {
		return nil, err
	}

	return t, nil
}

func (s *Service) saveContext(id string, data *context) error {
	src, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal transitional payload: %w", err)
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

	logger.Debugf("sending state msg: %+v\n", stateMsg)

	for _, handler := range l.MsgEvents() {
		handler <- stateMsg
	}
}

// HandleOutbound handles outbound messages.
func (s *Service) HandleOutbound(_ service.DIDCommMsg, _, _ string) (string, error) {
	// TODO implement
	return "", errors.New("not implemented")
}

func (s *Service) currentContext(msg service.DIDCommMsg, ctx service.DIDCommContext, opts Options) (*context, error) {
	if msg.Type() == InvitationMsgType || msg.Type() == HandshakeReuseMsgType {
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

		stateName := StateNameInitial
		if msg.Type() == HandshakeReuseMsgType {
			stateName = StateNameAwaitResponse
		}

		myContext.CurrentStateName = stateName

		if opts != nil {
			myContext.RouterConnections = opts.RouterConnections()
			myContext.ReuseConnection = opts.ReuseConnection()
			myContext.ReuseAnyConnection = opts.ReuseAnyConnection()
			myContext.MyLabel = opts.MyLabel()
		}

		return myContext, s.saveContext(msg.ID(), myContext)
	}

	thid, err := msg.ThreadID()
	if err != nil {
		return nil, fmt.Errorf("no thread id found in msg of type [%s]: %w", msg.Type(), err)
	}

	return s.loadContext(thid)
}

// AcceptInvitation from another agent and return the connection ID.
func (s *Service) AcceptInvitation(i *Invitation, options Options) (string, error) {
	msg := service.NewDIDCommMsgMap(i)

	err := validateInvitationAcceptance(msg, s.myMediaTypeProfiles, options)
	if err != nil {
		return "", fmt.Errorf("unable to accept invitation: %w", err)
	}

	ctx := &callback{
		msg: msg,
	}

	ctx.ctx, err = s.currentContext(msg, service.EmptyDIDCommContext(), options)
	if err != nil {
		return "", fmt.Errorf("failed to create context for invitation: %w", err)
	}

	connID, err := s.handleCallback(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to accept invitation : %w", err)
	}

	return connID, nil
}

// SaveInvitation created by the outofband client.
func (s *Service) SaveInvitation(i *Invitation) error {
	target, err := chooseTarget(i.Services)
	if err != nil {
		return fmt.Errorf("failed to choose a target to connect against : %w", err)
	}

	// TODO where should we save this invitation? - https://github.com/hyperledger/aries-framework-go/issues/1547
	err = s.connections.SaveInvitation(i.ID+"-TODO", i)
	if err != nil {
		return fmt.Errorf("failed to save oob invitation : %w", err)
	}

	logger.Debugf("saved invitation: %+v", i)

	err = s.didSvc.SaveInvitation(&didexchange.OOBInvitation{
		ID:                uuid.New().String(),
		ThreadID:          i.ID,
		TheirLabel:        i.Label,
		Target:            target,
		MediaTypeProfiles: i.Accept,
	})
	if err != nil {
		return fmt.Errorf("the didexchange service failed to save the oob invitation : %w", err)
	}

	return nil
}

func listener(
	callbacks chan *callback,
	didEvents chan service.StateMsg,
	handleCallbackFunc func(*callback) (string, error),
	handleDidEventFunc func(msg service.StateMsg) error) func() {
	return func() {
		for {
			select {
			case c := <-callbacks:
				switch c.msg.Type() {
				case InvitationMsgType, HandshakeReuseMsgType, OldInvitationMsgType:
					_, err := handleCallbackFunc(c)
					if err != nil {
						logutil.LogError(logger, Name, "handleCallback", err.Error(),
							logutil.CreateKeyValueString("msgType", c.msg.Type()),
							logutil.CreateKeyValueString("msgID", c.msg.ID()))

						continue
					}
				default:
					logutil.LogError(logger, Name, "callbackChannel", "unsupported msg type",
						logutil.CreateKeyValueString("msgType", c.msg.Type()),
						logutil.CreateKeyValueString("msgID", c.msg.ID()))
				}
			case e := <-didEvents:
				err := handleDidEventFunc(e)
				if errors.Is(err, errIgnoredDidEvent) {
					logutil.LogDebug(logger, Name, "handleDIDEvent", err.Error())
				}

				if err != nil && !errors.Is(err, errIgnoredDidEvent) {
					logutil.LogError(logger, Name, "handleDIDEvent", err.Error())
				}
			}
		}
	}
}

func (s *Service) handleCallback(c *callback) (string, error) {
	switch c.msg.Type() {
	case InvitationMsgType, OldInvitationMsgType:
		return s.handleInvitationCallback(c)
	case HandshakeReuseMsgType:
		return "", s.handleHandshakeReuseCallback(c)
	default:
		return "", fmt.Errorf("unsupported message type: %s", c.msg.Type())
	}
}

func (s *Service) handleInvitationCallback(c *callback) (string, error) {
	logger.Debugf("input: %+v", c)
	logger.Debugf("context: %+v", c.ctx)

	err := validateInvitationAcceptance(c.msg, s.myMediaTypeProfiles, &userOptions{
		myLabel:           c.ctx.MyLabel,
		routerConnections: c.ctx.RouterConnections,
		reuseAnyConn:      c.ctx.ReuseAnyConnection,
		reuseConn:         c.ctx.ReuseConnection,
	})
	if err != nil {
		return "", fmt.Errorf("unable to handle invitation: %w", err)
	}

	c.ctx.DIDExchangeInv, c.ctx.Invitation, err = decodeDIDInvitationAndOOBInvitation(c)
	if err != nil {
		return "", fmt.Errorf("handleInvitationCallback: failed to decode callback message : %w", err)
	}

	err = s.handleContext(c.ctx)
	if err != nil {
		return "", fmt.Errorf("failed to handle invitation: %w", err)
	}

	return c.ctx.ConnectionID, nil
}

func (s *Service) handleHandshakeReuseCallback(c *callback) error {
	logger.Debugf("input: %+v", c)

	return s.handleContext(c.ctx)
}

func (s *Service) handleDIDEvent(e service.StateMsg) error {
	logger.Debugf("input: %+v", e)

	if e.Type != service.PostState || e.StateID != didexchange.StateIDCompleted {
		return errIgnoredDidEvent
	}

	props, ok := e.Properties.(didcommModel.Event)
	if !ok {
		return fmt.Errorf("handleDIDEvent: failed to cast did state msg properties")
	}

	connID := props.ConnectionID()

	record, err := s.connections.GetConnectionRecord(connID)
	if err != nil {
		return fmt.Errorf("handleDIDEvent: failed to get connection record: %w", err)
	}

	if record.ParentThreadID == "" {
		return fmt.Errorf("handleDIDEvent: ParentThreadID is empty")
	}

	return s.dispatchInvitationAttachment(record.ParentThreadID, record.MyDID, record.TheirDID)
}

func (s *Service) dispatchInvitationAttachment(invID, myDID, theirDID string) error {
	state, err := s.fetchAttachmentHandlingState(invID)
	if err != nil {
		return fmt.Errorf("failed to load attachment handling state : %w", err)
	}

	msg, err := s.extractDIDCommMsg(state)
	if err != nil {
		return fmt.Errorf("failed to extract DIDComm msg : %w", err)
	}

	state.Done = true

	// Save state as Done before dispatching message because the out-of-band protocol
	// has done its job in getting this far. The other protocol maintains its own state.
	err = s.save(state)
	if err != nil {
		return fmt.Errorf("failed to update state : %w", err)
	}

	logger.Debugf("dispatching inbound message of type: %s", msg.Type())

	_, err = s.inboundHandler().HandleInbound(msg, service.NewDIDCommContext(myDID, theirDID, nil))
	if err != nil {
		return fmt.Errorf("failed to dispatch message: %w", err)
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

// TODO only 1 attached request is to be processed from the array as discussed in:
//  - https://github.com/hyperledger/aries-rfcs/issues/468
//  - https://github.com/hyperledger/aries-rfcs/issues/451
//  This logic should be injected into the service.
func chooseAttachment(state *attachmentHandlingState) (*decorator.Attachment, error) {
	if !state.Done && len(state.Invitation.Requests) > 0 {
		return state.Invitation.Requests[0], nil
	}

	return nil, errors.New("not attachments in invitation")
}

func extractDIDCommMsgBytes(a *decorator.Attachment) ([]byte, error) {
	bytes, err := a.Data.Fetch()
	if err != nil {
		return nil, fmt.Errorf("extractDIDCommMsgBytes: %w", err)
	}

	return bytes, nil
}

func (s *Service) extractDIDCommMsg(state *attachmentHandlingState) (service.DIDCommMsg, error) {
	req, err := s.chooseAttachmentFunc(state)
	if err != nil {
		return nil, fmt.Errorf("failed to select an attachment: %w", err)
	}

	bytes, err := s.extractDIDCommMsgBytesFunc(req)
	if err != nil {
		return nil, fmt.Errorf("failed to extract didcomm message from attachment : %w", err)
	}

	msg, err := service.ParseDIDCommMsgMap(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse followup request : %w", err)
	}

	return msg, nil
}

func validateInvitationAcceptance(msg service.DIDCommMsg, myProfiles []string, opts Options) error { // nolint:gocyclo
	if msg.Type() != InvitationMsgType {
		return nil
	}

	if opts.ReuseAnyConnection() && opts.ReuseConnection() != "" {
		return errors.New("cannot reuse any connection and also reuse a specific connection")
	}

	inv := &Invitation{}

	err := msg.Decode(inv)
	if err != nil {
		return fmt.Errorf("validateInvitationAcceptance: failed to decode invitation: %w", err)
	}

	if opts.ReuseConnection() != "" {
		_, err = did.Parse(opts.ReuseConnection())
		if err != nil {
			return fmt.Errorf("validateInvitationAcceptance: not a valid DID [%s]: %w", opts.ReuseConnection(), err)
		}

		found := false

		for i := range inv.Services {
			found = opts.ReuseConnection() == inv.Services[i]
			if found {
				break
			}
		}

		if !found {
			return fmt.Errorf(
				"validateInvitationAcceptance: did [%s] not found in invitation services", opts.ReuseConnection())
		}
	}

	if !matchMediaTypeProfiles(inv.Accept, myProfiles) {
		return fmt.Errorf("no acceptable media type profile found in invitation, invitation Accept property: [%v], "+
			"agent mediatypeprofiles: [%v]", inv.Accept, myProfiles)
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

func decodeDIDInvitationAndOOBInvitation(c *callback) (*didexchange.OOBInvitation, *Invitation, error) {
	oobInv := &Invitation{}

	err := c.msg.Decode(oobInv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode out-of-band invitation mesesage : %w", err)
	}

	target, err := chooseTarget(oobInv.Services)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to choose a target to connect against : %w", err)
	}

	didInv := &didexchange.OOBInvitation{
		ID:                uuid.New().String(),
		ThreadID:          oobInv.ID,
		TheirLabel:        oobInv.Label,
		Target:            target,
		MyLabel:           c.ctx.MyLabel,
		MediaTypeProfiles: oobInv.Accept,
	}

	return didInv, oobInv, nil
}

//nolint:funlen,gocognit,gocyclo
func chooseTarget(svcs []interface{}) (interface{}, error) {
	for i := range svcs {
		switch svc := svcs[i].(type) {
		case string, *did.Service:
			return svc, nil
		case map[string]interface{}:
			var s did.Service

			decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{TagName: "json", Result: &s})
			if err != nil {
				return nil, fmt.Errorf("failed to initialize decoder : %w", err)
			}

			err = decoder.Decode(svc)
			//nolint:nestif
			if err != nil {
				var targetErr *mapstructure.Error

				if errors.As(err, &targetErr) {
					for _, er := range targetErr.Errors {
						// TODO this error check depend on mapstructure decoding 'ServiceEndpoint' section of service.
						// TODO Find a  better way to build it.
						// if serviceEndpoint is a string, explicitly convert it using model.NewDIDCommV1Endpoint().
						if strings.EqualFold(er, "'serviceEndpoint' expected a map, got 'string'") {
							uri, ok := svc["serviceEndpoint"].(string)
							if ok {
								s.ServiceEndpoint = model.NewDIDCommV1Endpoint(uri)
								return &s, nil
							}
						} else if strings.EqualFold(er, "'serviceEndpoint' expected a map, got 'slice'") {
							// if serviceEndpoint is a slice, explicitly convert each entry using the following call:
							// model.NewDIDCommV2Endpoint()
							seps, ok := svc["serviceEndpoint"].([]interface{})
							if ok {
								var (
									v2Endpoints []model.DIDCommV2Endpoint
									errs        []error
								)

								for _, sep := range seps {
									var v2Endpoint model.DIDCommV2Endpoint

									endpointDecoder, e := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
										TagName: "json", Result: &v2Endpoint,
									})
									if e != nil {
										errs = append(errs, fmt.Errorf("failed to initialize DIDComm V2 "+
											"ServiceEndpoint decoder: %w, skipping", e))

										continue
									}

									e = endpointDecoder.Decode(sep)
									if e != nil {
										errs = append(errs, fmt.Errorf("didComm V2 ServiceEndpoint decoding "+
											"failed: %w, skipping", e))

										continue
									}

									v2Endpoints = append(v2Endpoints, v2Endpoint)
								}

								if len(v2Endpoints) > 0 {
									s.ServiceEndpoint = model.NewDIDCommV2Endpoint(v2Endpoints)
									return &s, nil
								}

								if len(errs) > 0 {
									return nil, fmt.Errorf("failed to decode DIDComm V2 service endpoint of "+
										"service block: %v", errs)
								}
							}
						}
					}
				}

				return nil, fmt.Errorf("failed to decode service block : %w, svc: %#v", err, svc)
			}

			return &s, nil
		}
	}

	return nil, fmt.Errorf("invalid or no targets to choose from")
}

func isTheEnd(s state) bool {
	_, ok := s.(*stateDone)

	return ok
}

type eventProps struct {
	ConnID string `json:"conn_id"`
	Err    error  `json:"err"`
}

func (e *eventProps) ConnectionID() string {
	return e.ConnID
}

func (e *eventProps) Error() error {
	return e.Err
}

type userOptions struct {
	myLabel           string
	routerConnections []string
	reuseAnyConn      bool
	reuseConn         string
}

func (e *userOptions) MyLabel() string {
	return e.myLabel
}

func (e *userOptions) RouterConnections() []string {
	return e.routerConnections
}

func (e *userOptions) ReuseAnyConnection() bool {
	return e.reuseAnyConn
}

func (e *userOptions) ReuseConnection() string {
	return e.reuseConn
}

// All implements EventProperties interface.
func (e *eventProps) All() map[string]interface{} {
	return map[string]interface{}{
		"connectionID": e.ConnectionID(),
		"error":        e.Error(),
	}
}
