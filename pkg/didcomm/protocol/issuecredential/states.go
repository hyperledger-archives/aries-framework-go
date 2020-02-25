/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

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

	// states for Issuer
	stateNameProposalReceived = "proposal-received"
	stateNameOfferSent        = "offer-sent"
	stateNameRequestReceived  = "request-received"
	stateNameCredentialIssued = "credential-issued"

	// states for Holder
	stateNameProposalSent       = "proposal-sent"
	stateNameOfferReceived      = "offer-received"
	stateNameRequestSent        = "request-sent"
	stateNameCredentialReceived = "credential-received"
)

// state action for network call
type stateAction func(messenger service.Messenger) error

type metaData struct{}

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

// start state
type start struct{}

func (s *start) Name() string {
	return stateNameStart
}

func (s *start) CanTransitionTo(st state) bool {
	return st.Name() == stateNameProposalSent || st.Name() == stateNameProposalReceived
}

func (s *start) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *start) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// abandoning state
type abandoning struct{}

func (s *abandoning) Name() string {
	return stateNameAbandoning
}

func (s *abandoning) CanTransitionTo(_ state) bool {
	return false
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
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *done) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// proposalReceived state
type proposalReceived struct{}

func (s *proposalReceived) Name() string {
	return stateNameProposalReceived
}

func (s *proposalReceived) CanTransitionTo(_ state) bool {
	return false
}

func (s *proposalReceived) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *proposalReceived) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// offerSent state
type offerSent struct{}

func (s *offerSent) Name() string {
	return stateNameOfferSent
}

func (s *offerSent) CanTransitionTo(_ state) bool {
	return false
}

func (s *offerSent) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *offerSent) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// requestReceived state
type requestReceived struct{}

func (s *requestReceived) Name() string {
	return stateNameRequestReceived
}

func (s *requestReceived) CanTransitionTo(_ state) bool {
	return false
}

func (s *requestReceived) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *requestReceived) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// credentialIssued state
type credentialIssued struct{}

func (s *credentialIssued) Name() string {
	return stateNameCredentialIssued
}

func (s *credentialIssued) CanTransitionTo(_ state) bool {
	return false
}

func (s *credentialIssued) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *credentialIssued) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// proposalSent state
type proposalSent struct{}

func (s *proposalSent) Name() string {
	return stateNameProposalSent
}

func (s *proposalSent) CanTransitionTo(_ state) bool {
	return false
}

func (s *proposalSent) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *proposalSent) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// offerReceived state
type offerReceived struct{}

func (s *offerReceived) Name() string {
	return stateNameOfferReceived
}

func (s *offerReceived) CanTransitionTo(_ state) bool {
	return false
}

func (s *offerReceived) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *offerReceived) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// requestSent state
type requestSent struct{}

func (s *requestSent) Name() string {
	return stateNameRequestSent
}

func (s *requestSent) CanTransitionTo(_ state) bool {
	return false
}

func (s *requestSent) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *requestSent) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// credentialReceived state
type credentialReceived struct{}

func (s *credentialReceived) Name() string {
	return stateNameCredentialReceived
}

func (s *credentialReceived) CanTransitionTo(_ state) bool {
	return false
}

func (s *credentialReceived) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *credentialReceived) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}
