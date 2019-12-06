/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
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
)

const (
	initialWaitCount    = 2
	introduceeIndexNone = -1
)

var logger = log.New("aries-framework/introduce/service")

// InvitationEnvelope provides necessary information to the service through Continue(InvitationEnvelope) function.
// Dependency is fully controlled by the end-user, the correct logic is
// to provide the same interface during the state machine execution, interface depends on the participant.
// e.g We have introducer and two introducees, this is the usual flow.
// Dependency interfaces are different and depend on the participant.
// - destinations length is 2 and Invitation is <nil> (introducer)
// - destinations length is 0 and Invitation is not <nil> (introducee)
// - destinations length is 0 and Invitation is <nil> (introducee)
//
// Correct usage is described below:
// - Destinations length is 0 and Invitation is <nil> (introducee)
// - Destinations length is 0 and Invitation is not <nil> (introducee or introducer skip proposal)
// - Destinations length is 1 and Invitation is <nil> (introducer)
// - Destinations length is 1 and Invitation is not <nil> (introducer)
// - Destinations length is 2 and Invitation is <nil> (introducer)
// NOTE: The state machine logic depends on the combinations above.
type InvitationEnvelope interface {
	Invitation() *didexchange.Invitation
	Destinations() []*service.Destination
}

// metaData type to store data for internal usage
type metaData struct {
	record
	Msg      *service.DIDCommMsg
	ThreadID string
	// keeps a dependency for the protocol injected by Continue() function
	dependency InvitationEnvelope
	disapprove bool
	// err is used to determine whether callback was stopped
	// e.g the user received an action event and executes Stop(err) function
	// in that case `err` is equal to `err` which was passing to Stop function
	err error
}

type record struct {
	StateName string `json:"state_name,omitempty"`
	// WaitCount - how many introducees still need to approve the introduction proposal
	// (initial value = introducee count, e.g. 2)
	WaitCount int `json:"wait_count,omitempty"`
	// IntroduceeIndex keeps an introducee index of from whom we got an invitation
	IntroduceeIndex int                     `json:"introducee_index,omitempty"`
	Invitation      *didexchange.Invitation `json:"invitation,omitempty"`
}

// Service for introduce protocol
type Service struct {
	service.Action
	service.Message
	store       storage.Store
	callbacks   chan *metaData
	ctx         internalContext
	wg          sync.WaitGroup
	stop        chan struct{}
	closedMutex sync.Mutex
	closed      bool
}

// Provider contains dependencies for the DID exchange protocol and is typically created by using aries.Context()
type Provider interface {
	OutboundDispatcher() dispatcher.Outbound
	StorageProvider() storage.Provider
	Service(id string) (interface{}, error)
}

// Forwarder provides the possibility to forward an invitation
type Forwarder interface {
	// method should be implemented in didexchange service
	SendInvitation(pthID string, inv *didexchange.Invitation, dest *service.Destination) error
}

// New returns introduce service
func New(p Provider) (*Service, error) {
	store, err := p.StorageProvider().OpenStore(Introduce)
	if err != nil {
		return nil, err
	}

	didSvc, err := p.Service(didexchange.DIDExchange)
	if err != nil {
		return nil, err
	}

	forwarderSvc, ok := didSvc.(Forwarder)
	if !ok {
		return nil, errors.New("cast service to forwarder service failed")
	}

	svc := &Service{
		ctx: internalContext{
			Outbound:  p.OutboundDispatcher(),
			Forwarder: forwarderSvc,
		},
		store:     store,
		callbacks: make(chan *metaData),
		stop:      make(chan struct{}),
	}

	// start the listener
	svc.wg.Add(1)

	go svc.startInternalListener()

	return svc, nil
}

// Stop stops service (callback listener)
func (s *Service) Stop() error {
	s.closedMutex.Lock()
	defer s.closedMutex.Unlock()

	if s.closed {
		return errors.New("server was already stopped")
	}

	close(s.stop)
	s.closed = true
	s.wg.Wait()

	return nil
}

// startInternalListener listens to messages in gochannel for callback messages from clients.
func (s *Service) startInternalListener() {
	for {
		select {
		case msg := <-s.callbacks:
			// if no error - do handle or it was disapproved
			if msg.err == nil || msg.disapprove {
				msg.err = s.handle(msg, nil)
			}

			// no error - continue
			if msg.err == nil {
				continue
			}

			msg.StateName = stateNameAbandoning

			if err := s.handle(msg, nil); err != nil {
				logger.Errorf("listener handle: %s", err)
			}
		case <-s.stop:
			logger.Infof("the callback listener was stopped")
			s.wg.Done()

			return
		}
	}
}

func (s *Service) doHandle(msg *service.DIDCommMsg, outbound bool) (*metaData, error) {
	thID, err := msg.ThreadID()
	if err != nil {
		return nil, err
	}

	logger.Infof("thread id value for the message: %s", thID)

	rec, err := s.currentStateRecord(thID)
	if err != nil {
		return nil, err
	}

	current := stateFromName(rec.StateName)

	logger.Infof("current state: %s", current.Name())

	next, err := nextState(msg, rec, outbound)
	if err != nil {
		return nil, err
	}

	logger.Infof("state will transition from %q to %q if the msgType is processed", current.Name(), next.Name())

	if !current.CanTransitionTo(next) {
		return nil, fmt.Errorf("invalid state transition: %s -> %s", current.Name(), next.Name())
	}

	logger.Infof("sent pre event for state %s", next.Name())

	// sets the next state name
	rec.StateName = next.Name()

	return &metaData{
		record:   *rec,
		Msg:      msg,
		ThreadID: thID,
	}, nil
}

// InvitationReceived is used to finish the state machine
// the function should be called by didexchange after receiving an invitation
func (s *Service) InvitationReceived(thID string) error {
	payload, err := json.Marshal(&model.Ack{
		Type:   AckMsgType,
		ID:     uuid.New().String(),
		Thread: &decorator.Thread{ID: thID},
	})
	if err != nil {
		return fmt.Errorf("invitation received marshal: %w", err)
	}

	msg, err := service.NewDIDCommMsg(payload)
	if err != nil {
		return fmt.Errorf("invitation received new DIDComm msg: %w", err)
	}

	_, err = s.HandleInbound(msg)

	return err
}

// HandleInbound handles inbound message (introduce protocol)
func (s *Service) HandleInbound(msg *service.DIDCommMsg) (string, error) {
	aEvent := s.ActionEvent()

	logger.Infof("entered into HandleInbound: %v", msg.Header)
	// throw error if there is no action event registered for inbound messages
	if aEvent == nil {
		return "", errors.New("no clients are registered to handle the message")
	}

	mData, err := s.doHandle(msg, false)
	if err != nil {
		return "", err
	}

	// trigger action event based on message type for inbound messages
	if canTriggerActionEvents(msg) {
		aEvent <- s.newDIDCommActionMsg(mData)
		return "", nil
	}

	// if no action event is triggered, continue the execution
	return "", s.handle(mData, nil)
}

// HandleOutbound handles outbound message (introduce protocol)
func (s *Service) HandleOutbound(msg *service.DIDCommMsg, dest *service.Destination) error {
	logger.Infof("entered into HandleOutbound: %v", msg.Header)

	mData, err := s.doHandle(msg, true)
	if err != nil {
		return err
	}

	return s.handle(mData, dest)
}

// sendMsgEvents triggers the message events.
func (s *Service) sendMsgEvents(msg *service.StateMsg) {
	// trigger the message events
	for _, handler := range s.MsgEvents() {
		handler <- *msg
	}
}

// newDIDCommActionMsg creates new DIDCommAction message
func (s *Service) newDIDCommActionMsg(msg *metaData) service.DIDCommAction {
	// create the message for the channel
	// trigger the registered action event
	actionStop := func(err error) {
		// if introducee received Proposal disapprove must be true
		if msg.Msg.Header.Type == ProposalMsgType {
			msg.disapprove = true
		}

		msg.err = err
		s.processCallback(msg)
	}

	return service.DIDCommAction{
		ProtocolName: Introduce,
		Message:      msg.Msg.Clone(),
		Continue: func(args interface{}) {
			// there is no way to receive another interface
			if dep, ok := args.(InvitationEnvelope); ok {
				msg.dependency = dep
				s.processCallback(msg)
				return
			}
			// sets an error to the message
			actionStop(errors.New("action dependency is missing"))
		},
		Stop: actionStop,
	}
}

func (s *Service) processCallback(msg *metaData) {
	// pass the callback data to internal channel. This is created to unblock consumer go routine and wrap the callback
	// channel internally.
	s.callbacks <- msg
}

func nextState(msg *service.DIDCommMsg, rec *record, outbound bool) (state, error) {
	switch msg.Header.Type {
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
		rec.WaitCount--

		if rec.WaitCount == 0 {
			return &delivering{}, nil
		}

		return &arranging{}, nil
	case ProblemReportMsgType:
		return &abandoning{}, nil
	case AckMsgType:
		return &done{}, nil
	default:
		return nil, fmt.Errorf("unrecognized msgType: %s", msg.Header.Type)
	}
}

func (s *Service) currentStateRecord(thID string) (*record, error) {
	src, err := s.store.Get(thID)
	if errors.Is(err, storage.ErrDataNotFound) {
		return &record{
			StateName:       stateNameStart,
			WaitCount:       initialWaitCount,
			IntroduceeIndex: introduceeIndexNone,
		}, nil
	}

	if err != nil {
		return nil, fmt.Errorf("cannot fetch state from store: thid=%s : %w", thID, err)
	}

	var r *record
	if err := json.Unmarshal(src, &r); err != nil {
		return nil, err
	}

	return r, nil
}

func (s *Service) save(id string, data interface{}) error {
	src, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("service save: %w", err)
	}

	return s.store.Put(id, src)
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
func canTriggerActionEvents(msg *service.DIDCommMsg) bool {
	switch msg.Header.Type {
	case ProposalMsgType, ResponseMsgType, RequestMsgType:
		return true
	}

	return false
}

func isNoOp(s state) bool {
	_, ok := s.(*noOp)
	return ok
}

// isSkipProposal is a helper function to determine whether this is skip proposal or no
// the usage is correct when it is executed on the introducer side
func isSkipProposal(msg *metaData) bool {
	// the skip proposal can be determined only after receiving dependency
	// dependency is injected by the Continue function
	if msg.dependency == nil {
		return false
	}

	// if introducer provides an invitation this is definitely the skip proposal
	return msg.dependency.Invitation() != nil
}

// injectInvitation the function tries to set an invitation we got from introducee
func injectInvitation(msg *metaData) error {
	// we can inject invitation only when we received the Response message
	// the Response message comes always from introduce
	if msg.Msg.Header.Type != ResponseMsgType {
		return nil
	}

	// if we already have an invitation it has more priority
	// the second invitation is not important for us and we are ignoring it
	if msg.Invitation != nil {
		return nil
	}

	// increases counter to determine from who we got an invitation
	msg.IntroduceeIndex++

	var resp *Response
	if err := json.Unmarshal(msg.Msg.Payload, &resp); err != nil {
		return err
	}

	// sets an invitation to which will be forwarded later
	msg.Invitation = resp.Invitation

	return nil
}

func (s *Service) handle(msg *metaData, dest *service.Destination) error {
	logger.Infof("entered into private handle message: %v ", msg.Msg.Header)

	// after receiving a response we need to determine whether it is skip proposal or no
	// if this is skip proposal we do not need to send a proposal to another introducee
	// we just simply go to Delivering state
	if msg.Msg.Header.Type == ResponseMsgType && isSkipProposal(msg) {
		msg.StateName = stateNameDelivering
	}

	next := stateFromName(msg.StateName)

	logger.Infof("next valid state to transition -> %s ", next.Name())

	var err error
	for !isNoOp(next) {
		next, err = s.execute(next, msg, dest)
		if err != nil {
			return fmt.Errorf("execute: %w", err)
		}
	}

	return nil
}

func (s *Service) execute(next state, msg *metaData, dest *service.Destination) (state, error) {
	s.sendMsgEvents(&service.StateMsg{
		ProtocolName: Introduce,
		Type:         service.PreState,
		Msg:          msg.Msg.Clone(),
		StateID:      next.Name(),
	})
	logger.Infof("sent pre event for state %s", next.Name())

	var (
		followup state
		err      error
	)

	if err = injectInvitation(msg); err != nil {
		return nil, fmt.Errorf("inject invitation: %w", err)
	}

	if dest != nil {
		followup, err = next.ExecuteOutbound(s.ctx, msg, dest)
	} else {
		followup, err = next.ExecuteInbound(s.ctx, msg)
	}

	if err != nil {
		return nil, fmt.Errorf("execute state %s %w", next.Name(), err)
	}

	logger.Infof("finish execute next state: %s", next.Name())

	// sets the next state name
	msg.StateName = next.Name()

	if err = s.save(msg.ThreadID, msg.record); err != nil {
		return nil, fmt.Errorf("failed to persist state %s %w", next.Name(), err)
	}

	logger.Infof("persisted the connection using %s and updated the state to %s", msg.ThreadID, next.Name())

	s.sendMsgEvents(&service.StateMsg{
		ProtocolName: Introduce,
		Type:         service.PostState,
		Msg:          msg.Msg.Clone(),
		StateID:      next.Name(),
	})
	logger.Infof("sent post event for state %s", next.Name())

	return followup, nil
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
