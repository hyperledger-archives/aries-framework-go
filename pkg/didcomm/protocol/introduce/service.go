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

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
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
)

const initialWaitCount = 2

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
// - Destinations length is 0 and Invitation is not <nil> (introducee with invitation)
// - Destinations length is 1 and Invitation is not <nil> (introducer skip proposal)
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
	// err is used to determine whether callback was stopped
	// e.g the user received an action event and executes Stop(err) function
	// in that case `err` is equal to `err` which was passing to Stop function
	err error
}

type record struct {
	StateName string
	// WaitCount - how many introducees still need to approve the introduction proposal
	// (initial value = introducee count, e.g. 2)
	WaitCount int
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
}

// New returns introduce service
func New(p Provider) (*Service, error) {
	store, err := p.StorageProvider().OpenStore(Introduce)
	if err != nil {
		return nil, err
	}

	svc := &Service{
		ctx: internalContext{
			Outbound: p.OutboundDispatcher(),
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
			// if no error - do handle
			if msg.err == nil {
				msg.err = s.handle(msg, nil)
			}

			// no error - continue
			if msg.err == nil {
				continue
			}

			if err := s.abandon(msg.ThreadID, msg.Msg, msg.err); err != nil {
				logger.Errorf("process callback : %s", err)
			}
		case <-s.stop:
			logger.Infof("the callback listener was stopped")
			s.wg.Done()

			return
		}
	}
}

// abandon updates the state to abandoned and trigger failure event.
func (s *Service) abandon(thID string, msg *service.DIDCommMsg, _ error) error {
	// update the state to abandoned
	if err := s.save(thID, &abandoning{}); err != nil {
		return fmt.Errorf("save abandoning sate: %w", err)
	}

	// TODO: add received error to Properties
	// send the message event
	s.sendMsgEvents(&service.StateMsg{
		ProtocolName: Introduce,
		Type:         service.PostState,
		Msg:          msg.Clone(),
		StateID:      stateNameAbandoning,
	})

	return nil
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

	current, err := stateFromName(rec.StateName)
	if err != nil {
		return nil, err
	}

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

	return &metaData{
		record: record{
			StateName: next.Name(),
			WaitCount: rec.WaitCount,
		},
		Msg:      msg,
		ThreadID: thID,
	}, nil
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

func (s *Service) sendRequest(msg *service.DIDCommMsg, dest *service.Destination) error {
	return nil
}

// HandleOutbound handles outbound message (introduce protocol)
func (s *Service) HandleOutbound(msg *service.DIDCommMsg, dest *service.Destination) error {
	logger.Infof("entered into HandleOutbound: %v", msg.Header)

	// request is not a part of any state machine, so we just need to send a request
	if msg.Header.Type == RequestMsgType {
		return s.sendRequest(msg, dest)
	}

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

// sendActionEvent triggers the action event. This function stores the state of current processing and passes a callback
// function in the event message.
func (s *Service) newDIDCommActionMsg(msg *metaData) service.DIDCommAction {
	// create the message for the channel
	// trigger the registered action event
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
			msg.err = errors.New("action dependency is missing")
			s.processCallback(msg)
		},
		Stop: func(err error) {
			// sets an error to the message
			msg.err = err
			s.processCallback(msg)
		},
	}
}

func (s *Service) processCallback(msg *metaData) {
	// pass the callback data to internal channel. This is created to unblock consumer go routine and wrap the callback
	// channel internally.
	s.callbacks <- msg
}

func nextState(msg *service.DIDCommMsg, rec *record, outbound bool) (state, error) {
	switch msg.Header.Type {
	case ProposalMsgType:
		if outbound {
			return &arranging{}, nil
		}

		return &deciding{}, nil
	case ResponseMsgType:
		if outbound {
			return &waiting{}, nil
		}

		rec.WaitCount--

		if rec.WaitCount == 0 {
			return &delivering{}, nil
		}

		return &arranging{}, nil
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
			StateName: stateNameStart,
			WaitCount: initialWaitCount,
		}, nil
	}

	if err != nil {
		return nil, fmt.Errorf("cannot fetch state from store: thid=%s err=%s", thID, err)
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
func stateFromName(name string) (state, error) {
	switch name {
	case stateNameNoop:
		return &noOp{}, nil
	case stateNameStart:
		return &start{}, nil
	case stateNameDone:
		return &done{}, nil
	case stateNameArranging:
		return &arranging{}, nil
	case stateNameDelivering:
		return &delivering{}, nil
	case stateNameConfirming:
		return &confirming{}, nil
	case stateNameAbandoning:
		return &abandoning{}, nil
	case stateNameDeciding:
		return &deciding{}, nil
	case stateNameWaiting:
		return &waiting{}, nil
	default:
		return nil, fmt.Errorf("invalid state name %s", name)
	}
}

// canTriggerActionEvents checks if the incoming message can trigger an action event
func canTriggerActionEvents(msg *service.DIDCommMsg) bool {
	// TODO: need to check more msg.Header.Type
	return msg.Header.Type == ProposalMsgType || msg.Header.Type == ResponseMsgType
}

func isNoOp(s state) bool {
	_, ok := s.(*noOp)
	return ok
}

func (s *Service) handle(msg *metaData, dest *service.Destination) error {
	logger.Infof("entered into private handle message: %v ", msg.Msg.Header)
	// if we got one destination value, this is definitely skip proposal
	if msg.dependency != nil && len(msg.dependency.Destinations()) == 1 {
		msg.StateName = stateNameDelivering
	}

	next, err := stateFromName(msg.StateName)
	if err != nil {
		return fmt.Errorf("state from name: %w", err)
	}

	logger.Infof("next valid state to transition -> %s ", next.Name())

	for !isNoOp(next) {
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

		if dest != nil {
			followup, err = next.ExecuteOutbound(s.ctx, msg, dest)
		} else {
			followup, err = next.ExecuteInbound(s.ctx, msg)
		}

		if err != nil {
			return fmt.Errorf("execute state %s %w", next.Name(), err)
		}

		logger.Infof("finish execute next state: %s", next.Name())

		if err = s.save(msg.ThreadID, record{
			StateName: next.Name(),
			WaitCount: msg.WaitCount,
		}); err != nil {
			return fmt.Errorf("failed to persist state %s %w", next.Name(), err)
		}

		logger.Infof("persisted the connection using %s and updated the state to %s", msg.ThreadID, next.Name())

		s.sendMsgEvents(&service.StateMsg{
			ProtocolName: Introduce,
			Type:         service.PostState,
			Msg:          msg.Msg.Clone(),
			StateID:      next.Name(),
		})
		logger.Infof("sent post event for state %s", next.Name())

		next = followup
	}

	return nil
}

// Name returns service name
func (s *Service) Name() string {
	return Introduce
}

// Accept msg checks the msg type
func (s *Service) Accept(msgType string) bool {
	switch msgType {
	case ProposalMsgType, RequestMsgType, ResponseMsgType, AckMsgType:
		return true
	}

	return false
}
