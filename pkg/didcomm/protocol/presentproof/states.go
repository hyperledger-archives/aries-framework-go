/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

const (
	// common states
	stateNameStart      = "start"
	stateNameAbandoning = "abandoning"
	stateNameDone       = "done"
	stateNameNoop       = "noop"

	// states for Verifier
	stateNameRequestSent          = "request-sent"
	stateNamePresentationReceived = "presentation-received"
	stateNameProposalReceived     = "proposal-received"

	// states for Prover
	stateNameRequestReceived  = "request-received"
	stateNamePresentationSent = "presentation-sent"
	stateNameProposalSent     = "proposal-sent"
)

const (
	codeInternalError = "internal"
	codeRejectedError = "rejected"
)

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
	case stateNameRequestSent, stateNameProposalReceived:
		return true
	// Prover
	case stateNameProposalSent, stateNameRequestReceived:
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

func (s *abandoning) ExecuteInbound(md *metaData) (state, stateAction, error) {
	// if code is not provided it means we do not need to notify the another agent
	if s.Code == "" {
		return &done{}, zeroAction, nil
	}

	var code = model.Code{Code: s.Code}

	// if the protocol was stopped by the user we will set the rejected error code
	if errors.As(md.err, &customError{}) {
		code = model.Code{Code: codeRejectedError}
	}

	thID, err := md.Msg.ThreadID()
	if err != nil {
		return nil, nil, fmt.Errorf("threadID: %w", err)
	}

	return &done{}, func(messenger service.Messenger) error {
		return messenger.ReplyToNested(thID, service.NewDIDCommMsgMap(&model.ProblemReport{
			Type:        ProblemReportMsgType,
			Description: code,
		}), md.MyDID, md.TheirDID)
	}, nil
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
		st.Name() == stateNameProposalSent ||
		st.Name() == stateNameAbandoning
}

func (s *requestReceived) ExecuteInbound(md *metaData) (state, stateAction, error) {
	if md.presentation != nil {
		return &presentationSent{}, zeroAction, nil
	}

	return &proposalSent{}, zeroAction, nil
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
		st.Name() == stateNameProposalReceived ||
		st.Name() == stateNameAbandoning
}

func (s *requestSent) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *requestSent) ExecuteOutbound(md *metaData) (state, stateAction, error) {
	// creates the state's action
	action := func(messenger service.Messenger) error {
		return messenger.Send(md.Msg, md.MyDID, md.TheirDID)
	}

	return &noOp{}, action, nil
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

func (s *presentationSent) ExecuteInbound(md *metaData) (state, stateAction, error) {
	if md.presentation == nil {
		return nil, nil, errors.New("presentation was not provided")
	}

	// creates the state's action
	action := func(messenger service.Messenger) error {
		// sets message type
		md.presentation.Type = PresentationMsgType
		return messenger.ReplyTo(md.Msg.ID(), service.NewDIDCommMsgMap(md.presentation))
	}

	return &noOp{}, action, nil
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

// proposalSent the Prover's state
type proposalSent struct{}

func (s *proposalSent) Name() string {
	return stateNameProposalSent
}

func (s *proposalSent) CanTransitionTo(st state) bool {
	return st.Name() == stateNameRequestReceived ||
		st.Name() == stateNameAbandoning
}

func (s *proposalSent) ExecuteInbound(md *metaData) (state, stateAction, error) {
	if md.proposePresentation == nil {
		return nil, nil, errors.New("propose-presentation was not provided")
	}

	// creates the state's action
	action := func(messenger service.Messenger) error {
		// sets message type
		md.proposePresentation.Type = ProposePresentationMsgType
		return messenger.ReplyTo(md.Msg.ID(), service.NewDIDCommMsgMap(md.proposePresentation))
	}

	return &noOp{}, action, nil
}

func (s *proposalSent) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// proposalReceived the Verifier's state
type proposalReceived struct{}

func (s *proposalReceived) Name() string {
	return stateNameProposalReceived
}

func (s *proposalReceived) CanTransitionTo(st state) bool {
	return st.Name() == stateNameRequestSent ||
		st.Name() == stateNameAbandoning
}

func (s *proposalReceived) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *proposalReceived) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}
