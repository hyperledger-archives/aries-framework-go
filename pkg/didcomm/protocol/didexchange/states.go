/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import "fmt"

// The did-exchange protocol's state.
type state interface {
	Name() string
	CanTransitionTo(new state) bool
}

// Returns the state towards which the protocol will transition to if the msgType is processed.
func stateFromMsgType(msgType string) (state, error) {
	var s state
	switch msgType {
	case connectionInvite:
		s = &invited{}
	case connectionRequest:
		s = &requested{}
	case connectionResponse:
		s = &responded{}
	case connectionAck:
		s = &completed{}
	default:
		return nil, fmt.Errorf("unrecognized msgType: %s", msgType)
	}
	return s, nil
}

// Returns the state representing the name.
func stateFromName(name string) (state, error) {
	all := []state{&null{}, &invited{}, &requested{}, &responded{}, &completed{}}
	for _, s := range all {
		if s.Name() == name {
			return s, nil
		}
	}
	return nil, fmt.Errorf("invalid state name %s", name)
}

// null state
type null struct {
}

func (s *null) Name() string {
	return "null"
}

func (s *null) CanTransitionTo(new state) bool {
	return (&invited{}).Name() == new.Name() || (&requested{}).Name() == new.Name()
}

// invited state
type invited struct {
}

func (s *invited) Name() string {
	return "invited"
}

func (s *invited) CanTransitionTo(new state) bool {
	return (&requested{}).Name() == new.Name()
}

// requested state
type requested struct {
}

func (s *requested) Name() string {
	return "requested"
}

func (s *requested) CanTransitionTo(new state) bool {
	return (&responded{}).Name() == new.Name()
}

// responded state
type responded struct {
}

func (s *responded) Name() string {
	return "responded"
}

func (s *responded) CanTransitionTo(new state) bool {
	return (&completed{}).Name() == new.Name()
}

// completed state
type completed struct {
}

func (s *completed) Name() string {
	return "completed"
}

func (s *completed) CanTransitionTo(new state) bool {
	return false
}
