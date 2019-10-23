/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/common/metadata"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	// Introduce protocol name
	Introduce = "introduce"
	// IntroduceSpec defines the introduce spec
	IntroduceSpec = metadata.AriesCommunityDID + ";spec/introduce/1.0/"
	// SkipProposalMsgType defines the skip proposal (the introducer has a public invitation)
	// skip proposal is not part of protocol specification (internal usage)
	SkipProposalMsgType = "skip/proposal"
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

// metaData type to store data for internal usage
type metaData struct {
	record
	Msg      *service.DIDCommMsg
	ThreadID string
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
	store storage.Store
}

// New returns introduce service
func New(s storage.Provider) (*Service, error) {
	store, err := s.OpenStore(Introduce)
	if err != nil {
		return nil, err
	}

	return &Service{store: store}, nil
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
	logger.Infof("current state : %s", current.Name())

	next, err := nextState(msg, rec, outbound)
	if err != nil {
		return nil, err
	}

	logger.Infof("state will transition from %q to %q if the msgType is processed", current.Name(), next.Name())

	if !current.CanTransitionTo(next) {
		return nil, fmt.Errorf("invalid state transition: %s -> %s", current.Name(), next.Name())
	}

	// trigger message events
	s.sendMsgEvents(service.StateMsg{
		Type:         service.PreState,
		Msg:          msg,
		ProtocolName: Introduce,
		StateID:      next.Name(),
		Properties:   nil,
	})

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
func (s *Service) HandleInbound(msg *service.DIDCommMsg) error {
	aEvent := s.ActionEvent()

	logger.Infof("entered into HandleInbound: %v", msg.Header)
	// throw error if there is no action event registered for inbound messages
	if aEvent == nil {
		return errors.New("no clients are registered to handle the message")
	}

	// request is not a part of any state machine, so we just need to trigger an actionEvent
	if msg.Header.Type == RequestMsgType {
		return s.sendActionEvent(&metaData{Msg: msg}, aEvent)
	}

	mData, err := s.doHandle(msg, false)
	if err != nil {
		return err
	}

	// trigger action event based on message type for inbound messages
	if canTriggerActionEvents(msg) {
		return s.sendActionEvent(mData, aEvent)
	}

	// if no action event is triggered, continue the execution
	return s.handle(mData, nil)
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
func (s *Service) sendMsgEvents(msg service.StateMsg) {
	// trigger the message events
	for _, handler := range s.MsgEvents() {
		handler <- msg
	}
}

// sendEvent triggers the action event. This function stores the state of current processing and passes a callback
// function in the event message.
func (s *Service) sendActionEvent(msg *metaData, aEvent chan<- service.DIDCommAction) error {
	// save the incoming message in the store (to retrieve later when callback events are fired)
	ID := uuid.New().String()
	err := s.save(ID, msg)
	if err != nil {
		return fmt.Errorf("JSON marshalling of document failed: %w", err)
	}

	// create the message for the channel
	didCommAction := service.DIDCommAction{
		ProtocolName: Introduce,
		Message:      msg.Msg,
		Continue: func() {
			s.processCallback(ID, nil)
		},
		Stop: func(err error) {
			s.processCallback(ID, err)
		},
	}

	// trigger the registered action event
	aEvent <- didCommAction

	return nil
}

func (s *Service) processCallback(id string, err error) {}

func nextState(msg *service.DIDCommMsg, rec *record, outbound bool) (state, error) {
	switch msg.Header.Type {
	// SkipProposal is an artificial message type, we need to replace it with a real one
	case SkipProposalMsgType:
		msg.Payload = []byte(strings.Replace(string(msg.Payload), SkipProposalMsgType, ProposalMsgType, 1))
		rec.WaitCount--
		return &arranging{}, nil
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
	return msg.Header.Type == ProposalMsgType
}

func isNoOp(s state) bool {
	_, ok := s.(*noOp)
	return ok
}

func (s *Service) handle(msg *metaData, dest *service.Destination) error {
	logger.Infof("entered into private handle message: %v ", msg.Msg.Header)

	next, err := stateFromName(msg.StateName)
	if err != nil {
		return fmt.Errorf("invalid state name: %w", err)
	}
	logger.Infof("next valid state to transition -> %s ", next.Name())

	for !isNoOp(next) {
		s.sendMsgEvents(service.StateMsg{
			Type: service.PreState, Msg: msg.Msg, StateID: next.Name(),
		})
		logger.Infof("sent pre event for state %s", next.Name())

		var (
			followup state
			err      error
		)

		if dest != nil {
			followup, err = next.ExecuteOutbound(msg, dest)
		} else {
			followup, err = next.ExecuteInbound(msg)
		}

		if err != nil {
			return fmt.Errorf("failed to execute state %s %w", next.Name(), err)
		}

		logger.Infof("finish execute next state: %s", next.Name())

		if err = s.save(msg.ThreadID, record{
			StateName: next.Name(),
			WaitCount: msg.WaitCount,
		}); err != nil {
			return fmt.Errorf("failed to persist state %s %w", next.Name(), err)
		}

		logger.Infof("persisted the connection using %s and updated the state to %s", msg.ThreadID, next.Name())

		s.sendMsgEvents(service.StateMsg{
			Type: service.PostState, Msg: msg.Msg, StateID: next.Name(),
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
