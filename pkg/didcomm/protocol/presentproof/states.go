/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

const (
	// common states
	stateNameStart      = "start"
	stateNameAbandoning = "abandoning"
	stateNameDone       = "done"
	stateNameNoop       = "noop"

	// states for Verifier
	stateNameRequestSent                 = "request-sent"
	stateNamePresentationReceived        = "presentation-received"
	stateNameProposePresentationReceived = "propose-presentation-received"

	// states for Prover
	stateNameRequestReceived         = "request-received"
	stateNamePresentationSent        = "presentation-sent"
	stateNameProposePresentationSent = "propose-presentation-sent"
)

const codeInternalError = "internal"

// state action for network call
type stateAction func(messenger service.Messenger) error

// the protocol's state.
type state interface {
	// Name of this state.
	Name() string
	// Whether this state allows transitioning into the next state.
	CanTransitionTo(next state) bool
	// Executes this state, returning a followup state to be immediately executed as well.
	// The 'noOp' state should be returned if the state has no followup.
	ExecuteInbound(msg *metaData) (state, stateAction, error)
	ExecuteOutbound(msg *metaData) (state, stateAction, error)
}

// represents zero state's action
func zeroAction(service.Messenger) error { return nil }

// start state
type start struct{}

func (s *start) Name() string {
	return stateNameStart
}

func (s *start) CanTransitionTo(st state) bool {
	switch st.Name() {
	// Verifier
	case stateNameRequestSent, stateNameProposePresentationReceived:
		return true
	// Prover
	case stateNameProposePresentationSent, stateNameRequestReceived:
		return true
	}

	return false
}

func (s *start) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *start) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// abandoning state
type abandoning struct {
	Code string
}

func (s *abandoning) Name() string {
	return stateNameAbandoning
}

func (s *abandoning) CanTransitionTo(st state) bool {
	return st.Name() == stateNameDone
}

func (s *abandoning) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *abandoning) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// done state
type done struct{}

func (s *done) Name() string {
	return stateNameDone
}

func (s *done) CanTransitionTo(_ state) bool {
	return false
}

func (s *done) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return &noOp{}, zeroAction, nil
}

func (s *done) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// noOp state
type noOp struct{}

func (s *noOp) Name() string {
	return stateNameNoop
}

func (s *noOp) CanTransitionTo(_ state) bool {
	return false
}

func (s *noOp) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, errors.New("cannot execute no-op")
}

func (s *noOp) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, errors.New("cannot execute no-op")
}

// requestReceived the Prover's state
type requestReceived struct{}

func (s *requestReceived) Name() string {
	return stateNameRequestReceived
}

func (s *requestReceived) CanTransitionTo(st state) bool {
	return st.Name() == stateNamePresentationSent ||
		st.Name() == stateNameProposePresentationSent ||
		st.Name() == stateNameAbandoning
}

func (s *requestReceived) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *requestReceived) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// requestSent the Verifier's state
type requestSent struct{}

func (s *requestSent) Name() string {
	return stateNameRequestSent
}

func (s *requestSent) CanTransitionTo(st state) bool {
	return st.Name() == stateNamePresentationReceived ||
		st.Name() == stateNameProposePresentationReceived ||
		st.Name() == stateNameAbandoning
}

func (s *requestSent) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *requestSent) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// presentationSent the Prover's state
type presentationSent struct{}

func (s *presentationSent) Name() string {
	return stateNamePresentationSent
}

func (s *presentationSent) CanTransitionTo(st state) bool {
	return st.Name() == stateNameAbandoning ||
		st.Name() == stateNameDone
}

func (s *presentationSent) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *presentationSent) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// presentationReceived the Verifier's state
type presentationReceived struct{}

func (s *presentationReceived) Name() string {
	return stateNamePresentationReceived
}

func (s *presentationReceived) CanTransitionTo(st state) bool {
	return st.Name() == stateNameAbandoning ||
		st.Name() == stateNameDone
}

func (s *presentationReceived) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *presentationReceived) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// proposePresentationSent the Prover's state
type proposePresentationSent struct{}

func (s *proposePresentationSent) Name() string {
	return stateNameProposePresentationSent
}

func (s *proposePresentationSent) CanTransitionTo(st state) bool {
	return st.Name() == stateNameRequestReceived ||
		st.Name() == stateNameAbandoning
}

func (s *proposePresentationSent) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *proposePresentationSent) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// proposePresentationReceived the Verifier's state
type proposePresentationReceived struct{}

func (s *proposePresentationReceived) Name() string {
	return stateNameProposePresentationReceived
}

func (s *proposePresentationReceived) CanTransitionTo(st state) bool {
	return st.Name() == stateNameRequestSent ||
		st.Name() == stateNameAbandoning
}

func (s *proposePresentationReceived) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *proposePresentationReceived) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}
