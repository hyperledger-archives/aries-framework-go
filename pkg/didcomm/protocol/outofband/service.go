/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
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

	// StateInvited is this protocol's state after accepting an invitation.
	StateInvited = "invited"

	// TODO channel size - https://github.com/hyperledger/aries-framework-go/issues/246
	callbackChannelSize = 10

	transitionalPayloadKey = "transitional_payload_%s"
)

var logger = log.New(fmt.Sprintf("aries-framework/%s/service", Name))

var errIgnoredDidEvent = errors.New("ignored")

var errDIDCommAttachmentNotFound = errors.New("no didcomm attachment was found")

// Options is a container for optional values provided by the user.
type Options interface {
	// MyLabel is the label to share with the other agent in the subsequent did-exchange.
	MyLabel() string
	RouterConnections() []string
}

type didExchSvc interface {
	RespondTo(*didexchange.OOBInvitation, []string) (string, error)
	SaveInvitation(invitation *didexchange.OOBInvitation) error
}

// Service implements the Out-Of-Band protocol.
type Service struct {
	service.Action
	service.Message
	callbackChannel            chan *callback
	didSvc                     didExchSvc
	didEvents                  chan service.StateMsg
	store                      storage.Store
	connections                *connection.Recorder
	outboundHandler            service.OutboundHandler
	chooseRequestFunc          func(*myState) (*decorator.Attachment, bool)
	extractDIDCommMsgBytesFunc func(*decorator.Attachment) ([]byte, error)
	listenerFunc               func()
}

type callback struct {
	msg      service.DIDCommMsg
	myDID    string
	theirDID string
	options  Options
}

type myState struct {
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

// transitionalPayload keeps payload needed for Continue function to proceed with the action.
type transitionalPayload struct {
	Action
}

// Provider provides this service's dependencies.
type Provider interface {
	Service(id string) (interface{}, error)
	StorageProvider() storage.Provider
	ProtocolStateStorageProvider() storage.Provider
	OutboundMessageHandler() service.OutboundHandler
}

// New creates a new instance of the out-of-band service.
func New(p Provider) (*Service, error) {
	svc, err := p.Service(didexchange.DIDExchange)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize outofband service : %w", err)
	}

	didSvc, ok := svc.(didExchSvc)
	if !ok {
		return nil, errors.New("failed to cast the didexchange service to satisfy our dependency")
	}

	store, err := p.ProtocolStateStorageProvider().OpenStore(Name)
	if err != nil {
		return nil, fmt.Errorf("failed to open the store : %w", err)
	}

	err = p.ProtocolStateStorageProvider().SetStoreConfig(Name,
		storage.StoreConfiguration{TagNames: []string{transitionalPayloadKey}})
	if err != nil {
		return nil, fmt.Errorf("failed to set store config in protocol state store: %w", err)
	}

	connectionRecorder, err := connection.NewRecorder(p)
	if err != nil {
		return nil, fmt.Errorf("failed to open a connection.Lookup : %w", err)
	}

	s := &Service{
		callbackChannel:            make(chan *callback, callbackChannelSize),
		didSvc:                     didSvc,
		didEvents:                  make(chan service.StateMsg, callbackChannelSize),
		store:                      store,
		connections:                connectionRecorder,
		outboundHandler:            p.OutboundMessageHandler(),
		chooseRequestFunc:          chooseRequest,
		extractDIDCommMsgBytesFunc: extractDIDCommMsgBytes,
	}

	s.listenerFunc = listener(s.callbackChannel, s.didEvents, s.handleCallback, s.handleDIDEvent, &s.Message)

	didEventsSvc, ok := didSvc.(service.Event)
	if !ok {
		return nil, errors.New("failed to cast didexchange service to service.Event")
	}

	if err = didEventsSvc.RegisterMsgEvent(s.didEvents); err != nil {
		return nil, fmt.Errorf("failed to register for didexchange protocol msgs : %w", err)
	}

	go s.listenerFunc()

	return s, nil
}

// Name is this service's name.
func (s *Service) Name() string {
	return Name
}

// Accept determines whether this service can handle the given type of message.
func (s *Service) Accept(msgType string) bool {
	return msgType == InvitationMsgType || msgType == OldInvitationMsgType
}

// HandleInbound handles inbound messages.
func (s *Service) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) { //nolint:funlen
	logger.Debugf("receive inbound message : %s", msg)

	if !s.Accept(msg.Type()) {
		return "", fmt.Errorf("unsupported message type %s", msg.Type())
	}

	events := s.ActionEvent()
	if events == nil {
		return "", fmt.Errorf("no clients registered to handle action events for %s protocol", Name)
	}

	// TODO should request messages with no attachments be rejected?
	//  https://github.com/hyperledger/aries-rfcs/issues/451

	piid, err := msg.ThreadID()
	if err != nil {
		return "", fmt.Errorf("threadID: %w", err)
	}

	err = s.saveTransitionalPayload(piid, &transitionalPayload{
		Action: Action{
			PIID:         piid,
			Msg:          msg.Clone(),
			MyDID:        ctx.MyDID(),
			TheirDID:     ctx.TheirDID(),
			ProtocolName: Name,
		},
	})
	if err != nil {
		return "", fmt.Errorf("save transitional payload: %w", err)
	}

	go func() {
		sendMsgEvent(service.PreState, &s.Message, msg, &eventProps{})

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

				if err := s.deleteTransitionalPayload(piid); err != nil {
					logger.Errorf("delete transitional payload: %s", err)
				}

				s.callbackChannel <- &callback{
					msg:      msg,
					myDID:    ctx.MyDID(),
					theirDID: ctx.TheirDID(),
					options:  opts,
				}
			},
			Stop: func(_ error) {
				if err := s.deleteTransitionalPayload(piid); err != nil {
					logger.Errorf("delete transitional payload: %s", err)
				}
			},
		}

		events <- event

		logger.Debugf("dispatched event: %+v", event)
	}()

	return "", nil
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
	tPayload, err := s.getTransitionalPayload(piID)
	if err != nil {
		return fmt.Errorf("get transitional payload: %w", err)
	}

	go func(opts Options) {
		s.callbackChannel <- &callback{
			msg:      tPayload.Msg,
			myDID:    tPayload.MyDID,
			theirDID: tPayload.TheirDID,
			options:  opts,
		}
	}(opts)

	return s.deleteTransitionalPayload(tPayload.PIID)
}

// ActionStop allows stopping the action by the piID.
func (s *Service) ActionStop(piID string, _ error) error {
	tPayload, err := s.getTransitionalPayload(piID)
	if err != nil {
		return fmt.Errorf("get transitional payload: %w", err)
	}

	return s.deleteTransitionalPayload(tPayload.PIID)
}

func (s *Service) getTransitionalPayload(id string) (*transitionalPayload, error) {
	src, err := s.store.Get(fmt.Sprintf(transitionalPayloadKey, id))
	if err != nil {
		return nil, fmt.Errorf("store get: %w", err)
	}

	t := &transitionalPayload{}
	if err := json.Unmarshal(src, t); err != nil {
		return nil, err
	}

	return t, nil
}

func (s *Service) saveTransitionalPayload(id string, data *transitionalPayload) error {
	src, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal transitional payload: %w", err)
	}

	return s.store.Put(fmt.Sprintf(transitionalPayloadKey, id), src, storage.Tag{Name: transitionalPayloadKey})
}

func (s *Service) deleteTransitionalPayload(id string) error {
	return s.store.Delete(fmt.Sprintf(transitionalPayloadKey, id))
}

func sendMsgEvent(t service.StateMsgType, l *service.Message, msg service.DIDCommMsg, p service.EventProperties) {
	stateMsg := service.StateMsg{
		ProtocolName: Name,
		Type:         t,
		StateID:      StateInvited,
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

// AcceptInvitation from another agent and return the connection ID.
func (s *Service) AcceptInvitation(i *Invitation, myLabel string, routerConnections []string) (string, error) {
	connID, err := s.handleCallback(&callback{
		msg:     service.NewDIDCommMsgMap(i),
		options: &userOptions{myLabel: myLabel, routerConnections: routerConnections},
	})
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

	err = s.didSvc.SaveInvitation(&didexchange.OOBInvitation{
		ID:         uuid.New().String(),
		ThreadID:   i.ID,
		TheirLabel: i.Label,
		Target:     target,
		MediaTypes: i.Accept,
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
	handleDidEventFunc func(msg service.StateMsg) error,
	msgHandlers *service.Message) func() {
	return func() {
		for {
			select {
			case c := <-callbacks:
				switch c.msg.Type() {
				case InvitationMsgType, OldInvitationMsgType:
					connID, err := handleCallbackFunc(c)
					if err != nil {
						logutil.LogError(logger, Name, "handleCallback", err.Error(),
							logutil.CreateKeyValueString("msgType", c.msg.Type()),
							logutil.CreateKeyValueString("msgID", c.msg.ID()))

						go sendMsgEvent(service.PostState, msgHandlers, c.msg, &eventProps{Err: err})

						continue
					}

					go sendMsgEvent(service.PostState, msgHandlers, c.msg, &eventProps{ConnID: connID})
				default:
					logutil.LogError(logger, Name, "callbackChannel", "unsupported msg type",
						logutil.CreateKeyValueString("msgType", c.msg.Type()),
						logutil.CreateKeyValueString("msgID", c.msg.ID()))
				}
			case e := <-didEvents:
				err := handleDidEventFunc(e)
				if err != nil {
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
	default:
		return "", fmt.Errorf("unsupported message type: %s", c.msg.Type())
	}
}

func (s *Service) handleInvitationCallback(c *callback) (string, error) {
	logger.Debugf("input: %+v", c)

	didInv, oobInv, err := decodeDIDInvitationAndOOBInvitation(c)
	if err != nil {
		return "", fmt.Errorf("handleInvitationCallback: failed to decode callback message : %w", err)
	}

	connID, err := s.didSvc.RespondTo(didInv, c.options.RouterConnections())
	if err != nil {
		return "", fmt.Errorf("didexchange service failed to handle inbound invitation : %w", err)
	}

	state := &myState{
		ID:           didInv.ThreadID,
		ConnectionID: connID,
		Invitation:   oobInv,
	}

	err = s.save(state)
	if err != nil {
		return "", fmt.Errorf("failed to save my state : %w", err)
	}

	return connID, nil
}

func (s *Service) handleDIDEvent(e service.StateMsg) error { // nolint:gocyclo
	logger.Debugf("input: %+v", e)

	if e.Type != service.PostState || e.StateID != didexchange.StateIDCompleted {
		return errIgnoredDidEvent
	}

	props, ok := e.Properties.(didexchange.Event)
	if !ok {
		return fmt.Errorf("service.handleDIDEvent: failed to cast did state msg properties")
	}

	connID := props.ConnectionID()

	record, err := s.connections.GetConnectionRecord(connID)
	if err != nil {
		return fmt.Errorf("service.handleDIDEvent: failed to get connection record: %w", err)
	}

	if record.ParentThreadID == "" {
		return fmt.Errorf("service.handleDIDEvent: ParentThreadID is empty")
	}

	state, err := s.fetchMyState(record.ParentThreadID)
	if err != nil {
		return fmt.Errorf("service.handleDIDEvent: failed to load state : %w", err)
	}

	msg, err := s.extractDIDCommMsg(state)
	if err != nil && !errors.Is(err, errDIDCommAttachmentNotFound) {
		return fmt.Errorf("service.handleDIDEvent: failed to extract DIDComm msg : %w", err)
	}

	state.Done = true

	// Save state as Done before dispatching message because the out-of-band protocol
	// has done its job in getting this far. The other protocol maintains its own state.
	err = s.save(state)
	if err != nil {
		return fmt.Errorf("service.handleDIDEvent: failed to update state : %w", err)
	}

	if msg != nil {
		_, err = s.outboundHandler.HandleOutbound(msg, record.MyDID, record.TheirDID)
		if err != nil {
			return fmt.Errorf("service.handleDIDEvent: failed to dispatch message : %w", err)
		}
	}

	return nil
}

func (s *Service) save(state *myState) error {
	bytes, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to save state=%+v : %w", state, err)
	}

	err = s.store.Put(state.ID, bytes)
	if err != nil {
		return fmt.Errorf("failed to save state : %w", err)
	}

	return nil
}

func (s *Service) fetchMyState(id string) (*myState, error) {
	bytes, err := s.store.Get(id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch state using id=%s : %w", id, err)
	}

	state := &myState{}

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
func chooseRequest(state *myState) (*decorator.Attachment, bool) {
	if !state.Done && len(state.Invitation.Requests) > 0 {
		return state.Invitation.Requests[0], true
	}

	return nil, false
}

func extractDIDCommMsgBytes(a *decorator.Attachment) ([]byte, error) {
	bytes, err := a.Data.Fetch()
	if err != nil {
		return nil, fmt.Errorf("extractDIDCommMsgBytes: %w", err)
	}

	return bytes, nil
}

func (s *Service) extractDIDCommMsg(state *myState) (service.DIDCommMsg, error) {
	req, found := s.chooseRequestFunc(state)
	if !found {
		return nil, errDIDCommAttachmentNotFound
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
		ID:         uuid.New().String(),
		ThreadID:   oobInv.ID,
		TheirLabel: oobInv.Label,
		Target:     target,
		MyLabel:    c.options.MyLabel(),
		MediaTypes: oobInv.Accept,
	}

	return didInv, oobInv, nil
}

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
			if err != nil {
				return nil, fmt.Errorf("failed to decode service block : %w", err)
			}

			return &s, nil
		}
	}

	return nil, fmt.Errorf("invalid or no targets to choose from")
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
}

func (e *userOptions) MyLabel() string {
	return e.myLabel
}

func (e *userOptions) RouterConnections() []string {
	return e.routerConnections
}

// All implements EventProperties interface.
func (e *eventProps) All() map[string]interface{} {
	return map[string]interface{}{
		"connectionID": e.ConnectionID(),
		"error":        e.Error(),
	}
}
