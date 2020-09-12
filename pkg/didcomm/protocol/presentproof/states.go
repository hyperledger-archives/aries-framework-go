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
	// common states.
	stateNameStart     = "start"
	stateNameAbandoned = "abandoned"
	stateNameDone      = "done"
	stateNameNoop      = "noop"

	// states for Verifier.
	stateNameRequestSent          = "request-sent"
	stateNamePresentationReceived = "presentation-received"
	stateNameProposalReceived     = "proposal-received"

	// states for Prover.
	stateNameRequestReceived  = "request-received"
	stateNamePresentationSent = "presentation-sent"
	stateNameProposalSent     = "proposal-sent"
)

const (
	// error codes.
	codeInternalError = "internal"
	codeRejectedError = "rejected"

	jsonThread = "~thread"
)

// state action for network call.
type stateAction func(messenger service.Messenger) error

// the protocol's state.
type state interface {
	// Name of this state.
	Name() string
	// Whether this state allows transitioning into the next state.
	CanTransitionTo(next state) bool
	// Executes this state, returning a followup state to be immediately executed as well.
	// The 'noOp' state should be returned if the state has no followup.
	Execute(msg *metaData) (state, stateAction, error)
}

// represents zero state's action.
func zeroAction(service.Messenger) error { return nil }

// start state.
type start struct{}

func (s *start) Name() string {
	return stateNameStart
}

func (s *start) CanTransitionTo(st state) bool {
	switch st.Name() {
	// Verifier.
	case stateNameRequestSent, stateNameProposalReceived:
		return true
	// Prover.
	case stateNameProposalSent, stateNameRequestReceived:
		return true
	}

	return false
}

func (s *start) Execute(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: is not implemented yet", s.Name())
}

// abandoned state.
type abandoned struct {
	Code string
}

func (s *abandoned) Name() string {
	return stateNameAbandoned
}

func (s *abandoned) CanTransitionTo(st state) bool {
	return false
}

func (s *abandoned) Execute(md *metaData) (state, stateAction, error) {
	// if code is not provided it means we do not need to notify the another agent.
	// if we received ProblemReport message no need to answer.
	if s.Code == "" || md.Msg.Type() == ProblemReportMsgType {
		return &noOp{}, zeroAction, nil
	}

	code := model.Code{Code: s.Code}

	// if the protocol was stopped by the user we will set the rejected error code
	if errors.As(md.err, &customError{}) {
		code = model.Code{Code: codeRejectedError}
	}

	thID, err := md.Msg.ThreadID()
	if err != nil {
		return nil, nil, fmt.Errorf("threadID: %w", err)
	}

	return &noOp{}, func(messenger service.Messenger) error {
		return messenger.ReplyToNested(thID, service.NewDIDCommMsgMap(&model.ProblemReport{
			Type:        ProblemReportMsgType,
			Description: code,
		}), md.MyDID, md.TheirDID)
	}, nil
}

// done state.
type done struct{}

func (s *done) Name() string {
	return stateNameDone
}

func (s *done) CanTransitionTo(_ state) bool {
	return false
}

func (s *done) Execute(_ *metaData) (state, stateAction, error) {
	return &noOp{}, zeroAction, nil
}

// noOp state.
type noOp struct{}

func (s *noOp) Name() string {
	return stateNameNoop
}

func (s *noOp) CanTransitionTo(_ state) bool {
	return false
}

func (s *noOp) Execute(_ *metaData) (state, stateAction, error) {
	return nil, nil, errors.New("cannot execute no-op")
}

// requestReceived the Prover's state.
type requestReceived struct{}

func (s *requestReceived) Name() string {
	return stateNameRequestReceived
}

func (s *requestReceived) CanTransitionTo(st state) bool {
	return st.Name() == stateNamePresentationSent ||
		st.Name() == stateNameProposalSent ||
		st.Name() == stateNameAbandoned
}

func (s *requestReceived) Execute(md *metaData) (state, stateAction, error) {
	if md.presentation == nil {
		return &proposalSent{}, zeroAction, nil
	}

	var req *RequestPresentation

	if err := md.Msg.Decode(&req); err != nil {
		return nil, nil, err
	}

	return &presentationSent{WillConfirm: req.WillConfirm}, zeroAction, nil
}

// requestSent the Verifier's state.
type requestSent struct{}

func (s *requestSent) Name() string {
	return stateNameRequestSent
}

func (s *requestSent) CanTransitionTo(st state) bool {
	return st.Name() == stateNamePresentationReceived ||
		st.Name() == stateNameProposalReceived ||
		st.Name() == stateNameAbandoned
}

func forwardInitial(md *metaData) stateAction {
	return func(messenger service.Messenger) error {
		return messenger.Send(md.Msg, md.MyDID, md.TheirDID)
	}
}

func (s *requestSent) Execute(md *metaData) (state, stateAction, error) {
	if !canReplyTo(md.Msg) {
		var req *RequestPresentation

		if err := md.Msg.Decode(&req); err != nil {
			return nil, nil, err
		}

		md.AckRequired = req.WillConfirm

		return &noOp{}, forwardInitial(md), nil
	}

	if md.request == nil {
		return nil, nil, errors.New("request was not provided")
	}

	md.AckRequired = md.request.WillConfirm

	return &noOp{}, func(messenger service.Messenger) error {
		md.request.Type = RequestPresentationMsgType
		return messenger.ReplyTo(md.Msg.ID(), service.NewDIDCommMsgMap(md.request))
	}, nil
}

// presentationSent the Prover's state.
type presentationSent struct {
	WillConfirm bool
}

func (s *presentationSent) Name() string {
	return stateNamePresentationSent
}

func (s *presentationSent) CanTransitionTo(st state) bool {
	return st.Name() == stateNameAbandoned ||
		st.Name() == stateNameDone
}

func (s *presentationSent) Execute(md *metaData) (state, stateAction, error) {
	if md.presentation == nil {
		return nil, nil, errors.New("presentation was not provided")
	}

	// creates the state's action
	action := func(messenger service.Messenger) error {
		// sets message type
		md.presentation.Type = PresentationMsgType
		return messenger.ReplyTo(md.Msg.ID(), service.NewDIDCommMsgMap(md.presentation))
	}

	if !s.WillConfirm {
		return &done{}, action, nil
	}

	return &noOp{}, action, nil
}

// presentationReceived the Verifier's state.
type presentationReceived struct{}

func (s *presentationReceived) Name() string {
	return stateNamePresentationReceived
}

func (s *presentationReceived) CanTransitionTo(st state) bool {
	return st.Name() == stateNameAbandoned ||
		st.Name() == stateNameDone
}

func (s *presentationReceived) Execute(md *metaData) (state, stateAction, error) {
	if !md.AckRequired {
		return &done{}, zeroAction, nil
	}

	// creates the state's action
	action := func(messenger service.Messenger) error {
		return messenger.ReplyTo(md.Msg.ID(), service.NewDIDCommMsgMap(model.Ack{
			Type: AckMsgType,
		}))
	}

	return &done{}, action, nil
}

// proposalSent the Prover's state.
type proposalSent struct{}

func (s *proposalSent) Name() string {
	return stateNameProposalSent
}

func (s *proposalSent) CanTransitionTo(st state) bool {
	return st.Name() == stateNameRequestReceived ||
		st.Name() == stateNameAbandoned
}

func canReplyTo(msg service.DIDCommMsgMap) bool {
	_, ok := msg[jsonThread]
	return ok
}

func (s *proposalSent) Execute(md *metaData) (state, stateAction, error) {
	if !canReplyTo(md.Msg) {
		return &noOp{}, forwardInitial(md), nil
	}

	if md.proposePresentation == nil {
		return nil, nil, errors.New("propose-presentation was not provided")
	}

	return &noOp{}, func(messenger service.Messenger) error {
		md.proposePresentation.Type = ProposePresentationMsgType
		return messenger.ReplyTo(md.Msg.ID(), service.NewDIDCommMsgMap(md.proposePresentation))
	}, nil
}

// proposalReceived the Verifier's state.
type proposalReceived struct{}

func (s *proposalReceived) Name() string {
	return stateNameProposalReceived
}

func (s *proposalReceived) CanTransitionTo(st state) bool {
	return st.Name() == stateNameRequestSent ||
		st.Name() == stateNameAbandoned
}

func (s *proposalReceived) Execute(_ *metaData) (state, stateAction, error) {
	return &requestSent{}, zeroAction, nil
}
