/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"errors"
	"fmt"

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
	// ProposalMsgType defines the introduce proposal message type.
	ProposalMsgType = IntroduceSpec + "proposal"
	// RequestMsgType defines the introduce request message type.
	RequestMsgType = IntroduceSpec + "request"
	// ResponseMsgType defines the introduce response message type.
	ResponseMsgType = IntroduceSpec + "response"
	// AckMsgType defines the introduce ack message type.
	AckMsgType = IntroduceSpec + "ack"
)

var logger = log.New("aries-framework/introduce/service")

// eventMetadata type to store data for eventing. This is retrieved during callback.
type eventMetadata struct {
	Msg           *service.DIDCommMsg
	NextStateName string
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

// HandleInbound handles inbound message (introduce protocol)
func (s *Service) HandleInbound(msg *service.DIDCommMsg) error {
	aEvent := s.GetActionEvent()

	logger.Infof("entered into Handle: %v", msg.Header)
	// throw error if there is no action event registered for inbound messages
	if aEvent == nil {
		return errors.New("no clients are registered to handle the message")
	}

	thID, err := msg.ThreadID()
	if err != nil {
		return err
	}
	logger.Infof("thread id value for the message: %s", thID)

	current, err := s.currentState(thID)
	if err != nil {
		return err
	}
	logger.Infof("current state : %s", current.Name())

	next, err := nextState(msg)
	if err != nil {
		return err
	}

	logger.Infof("state will transition from %q to %q if the msgType is processed", current.Name(), next.Name())

	if !current.CanTransitionTo(next) {
		return fmt.Errorf("invalid state transition: %s -> %s", current.Name(), next.Name())
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

	// trigger action event based on message type for inbound messages
	if canTriggerActionEvents(msg) {
		return s.sendActionEvent(msg, aEvent, next)
	}

	// if no action event is triggered, continue the execution
	return s.handle(eventMetadata{
		Msg:           msg,
		NextStateName: next.Name(),
	})
}

// HandleOutbound handles outbound message (introduce protocol)
func (s *Service) HandleOutbound(msg *service.DIDCommMsg, destination *service.Destination) error {
	return errors.New("not implemented yet")
}

// sendMsgEvents triggers the message events.
func (s *Service) sendMsgEvents(msg service.StateMsg) {
	// trigger the message events
	for _, handler := range s.GetMsgEvents() {
		handler <- msg
	}
}

// sendEvent triggers the action event. This function stores the state of current processing and passes a callback
// function in the event message.
func (s *Service) sendActionEvent(msg *service.DIDCommMsg, aEvent chan<- service.DIDCommAction, nextState state) error {
	return nil
}

func nextState(msg *service.DIDCommMsg) (state, error) {
	switch msg.Header.Type {
	case ProposalMsgType:
		return &arranging{}, nil
	case ResponseMsgType:
		return &delivering{}, nil
	default:
		return nil, fmt.Errorf("unrecognized msgType: %s", msg.Header.Type)
	}
}

func (s *Service) currentState(thID string) (state, error) {
	name, err := s.store.Get(thID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return &start{}, nil
		}
		return nil, fmt.Errorf("cannot fetch state from store: thid=%s err=%s", thID, err)
	}

	return stateFromName(string(name))
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

func (s *Service) handle(_ eventMetadata) error {
	return errors.New("not implemented yet")
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
