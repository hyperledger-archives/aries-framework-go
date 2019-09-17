/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
)

const (
	stateNameNoop      = "noop"
	stateNameNull      = "null"
	stateNameInvited   = "invited"
	stateNameRequested = "requested"
	stateNameResponded = "responded"
	stateNameCompleted = "completed"
)

// The did-exchange protocol's state.
type state interface {
	// Name of this state.
	Name() string
	// Whether this state allows transitioning into the next state.
	CanTransitionTo(next state) bool
	// Executes this state, returning a followup state to be immediately executed as well.
	// The 'noOp' state should be returned if the state has no followup.
	Execute(msg dispatcher.DIDCommMsg) (followup state, err error)
}

// Returns the state towards which the protocol will transition to if the msgType is processed.
func stateFromMsgType(msgType string) (state, error) {
	switch msgType {
	case ConnectionInvite:
		return &invited{}, nil
	case ConnectionRequest:
		return &requested{}, nil
	case ConnectionResponse:
		return &responded{}, nil
	case ConnectionAck:
		return &completed{}, nil
	default:
		return nil, fmt.Errorf("unrecognized msgType: %s", msgType)
	}
}

// Returns the state representing the name.
func stateFromName(name string) (state, error) {
	switch name {
	// TODO: need clarification: noOp state was missing, was it a bug or feature?
	case stateNameNoop:
		return &noOp{}, nil
	case stateNameNull:
		return &null{}, nil
	case stateNameInvited:
		return &invited{}, nil
	case stateNameRequested:
		return &requested{}, nil
	case stateNameResponded:
		return &responded{}, nil
	case stateNameCompleted:
		return &completed{}, nil
	default:
		return nil, fmt.Errorf("invalid state name %s", name)
	}
}

type noOp struct {
}

func (s *noOp) Name() string {
	return stateNameNoop
}

func (s *noOp) CanTransitionTo(_ state) bool {
	return false
}

func (s *noOp) Execute(_ dispatcher.DIDCommMsg) (state, error) {
	return nil, errors.New("cannot execute no-op")
}

// null state
type null struct {
}

func (s *null) Name() string {
	return stateNameNull
}

func (s *null) CanTransitionTo(next state) bool {
	return stateNameInvited == next.Name() || stateNameRequested == next.Name()
}

func (s *null) Execute(msg dispatcher.DIDCommMsg) (state, error) {
	return &noOp{}, nil
}

// invited state
type invited struct {
}

func (s *invited) Name() string {
	return stateNameInvited
}

func (s *invited) CanTransitionTo(next state) bool {
	return stateNameRequested == next.Name()
}

func (s *invited) Execute(msg dispatcher.DIDCommMsg) (state, error) {
	if msg.Type != ConnectionInvite {
		return nil, fmt.Errorf("illegal msg type %s for state %s", msg.Type, s.Name())
	}
	if msg.Outbound {
		// illegal
		return nil, errors.New("outbound invitations are not allowed")
	}
	return &requested{}, nil
}

// requested state
type requested struct {
}

func (s *requested) Name() string {
	return stateNameRequested
}

func (s *requested) CanTransitionTo(next state) bool {
	return stateNameResponded == next.Name()
}

func (s *requested) Execute(msg dispatcher.DIDCommMsg) (state, error) {
	switch msg.Type {
	case ConnectionInvite:
		if msg.Outbound {
			return nil, fmt.Errorf("outbound invitations are not allowed for state %s", s.Name())
		}
		// send did-exchange Request
		return &noOp{}, nil
	case ConnectionRequest:
		if msg.Outbound {
			// send outbound Request
			return &noOp{}, nil
		}
		return &responded{}, nil
	default:
		return nil, fmt.Errorf("illegal msg type %s for state %s", msg.Type, s.Name())
	}
}

// responded state
type responded struct {
}

func (s *responded) Name() string {
	return stateNameResponded
}

func (s *responded) CanTransitionTo(next state) bool {
	return stateNameCompleted == next.Name()
}

func (s *responded) Execute(msg dispatcher.DIDCommMsg) (state, error) {
	switch msg.Type {
	case ConnectionRequest:
		if msg.Outbound {
			return nil, fmt.Errorf("outbound requests are not allowed for state %s", s.Name())
		}
		// send Response
		return &noOp{}, nil
	case ConnectionResponse:
		if msg.Outbound {
			// send response
			return &noOp{}, nil
		}
		return &completed{}, nil
	default:
		return nil, fmt.Errorf("illegal msg type %s for state %s", msg.Type, s.Name())
	}
}

// completed state
type completed struct {
}

func (s *completed) Name() string {
	return stateNameCompleted
}

func (s *completed) CanTransitionTo(next state) bool {
	return false
}

func (s *completed) Execute(msg dispatcher.DIDCommMsg) (state, error) {
	switch msg.Type {
	case ConnectionResponse:
		if msg.Outbound {
			return nil, fmt.Errorf("outbound responses are not allowed for state %s", s.Name())
		}
		// send ACK
		return &noOp{}, nil
	case ConnectionAck:
		// if msg.Outbound send ACK
		// otherwise save did-exchange connection
		return &noOp{}, nil
	default:
		return nil, fmt.Errorf("illegal msg type %s for state %s", msg.Type, s.Name())
	}
}
