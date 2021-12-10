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
	stateNameStart = "start"
	stateNameNoop  = "noop"

	// StateNameAbandoned is present proof protocol state 'abandoned'.
	StateNameAbandoned = "abandoned"
	// StateNameDone is present proof protocol state 'done'.
	StateNameDone = "done"

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
	webRedirect       = "~web-redirect"
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
	// Message properties required for further steps or next state transition.
	Properties() map[string]interface{}
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

func (s *start) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

// abandoned state.
type abandoned struct {
	V          string
	Code       string
	properties map[string]interface{}
}

func (s *abandoned) Name() string {
	return StateNameAbandoned
}

func (s *abandoned) CanTransitionTo(st state) bool {
	return false
}

func (s *abandoned) Execute(md *metaData) (state, stateAction, error) {
	// if code is not provided it means we do not need to notify the another agent.
	// if we received ProblemReport message no need to answer.
	if s.Code == "" || md.Msg.Type() == ProblemReportMsgTypeV2 || md.Msg.Type() == ProblemReportMsgTypeV3 {
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
		if s.V == SpecV3 {
			return messenger.ReplyToNested(service.NewDIDCommMsgMap(&model.ProblemReportV2{
				Type: ProblemReportMsgTypeV3,
				Body: model.ProblemReportV2Body{Code: code.Code, WebRedirect: md.properties[webRedirect]},
			}), &service.NestedReplyOpts{ThreadID: thID, MyDID: md.MyDID, TheirDID: md.TheirDID, V: getDIDVersion(s.V)})
		}

		return messenger.ReplyToNested(service.NewDIDCommMsgMap(&model.ProblemReport{
			Type:        ProblemReportMsgTypeV2,
			Description: code,
			WebRedirect: md.properties[webRedirect],
		}), &service.NestedReplyOpts{ThreadID: thID, MyDID: md.MyDID, TheirDID: md.TheirDID, V: getDIDVersion(s.V)})
	}, nil
}

func (s *abandoned) Properties() map[string]interface{} {
	return s.properties
}

// done state.
type done struct {
	V          string
	properties map[string]interface{}
}

func (s *done) Name() string {
	return StateNameDone
}

func (s *done) CanTransitionTo(_ state) bool {
	return false
}

func (s *done) Execute(_ *metaData) (state, stateAction, error) {
	return &noOp{}, zeroAction, nil
}

func (s *done) Properties() map[string]interface{} {
	return s.properties
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

func (s *noOp) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

// requestReceived the Prover's state.
type requestReceived struct {
	V string
}

func (s *requestReceived) Name() string {
	return stateNameRequestReceived
}

func (s *requestReceived) CanTransitionTo(st state) bool {
	return st.Name() == stateNamePresentationSent ||
		st.Name() == stateNameProposalSent ||
		st.Name() == StateNameAbandoned
}

func (s *requestReceived) Execute(md *metaData) (state, stateAction, error) {
	if md.presentation == nil && md.presentationV3 == nil {
		return &proposalSent{V: s.V}, zeroAction, nil
	}

	if s.V == SpecV3 {
		var req *RequestPresentationV3

		if err := md.Msg.Decode(&req); err != nil {
			return nil, nil, err
		}

		return &presentationSent{V: s.V, WillConfirm: req.Body.WillConfirm}, zeroAction, nil
	}

	var req *RequestPresentationV2

	if err := md.Msg.Decode(&req); err != nil {
		return nil, nil, err
	}

	return &presentationSent{V: s.V, WillConfirm: req.WillConfirm}, zeroAction, nil
}

func (s *requestReceived) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

// requestSent the Verifier's state.
type requestSent struct {
	V string
}

func (s *requestSent) Name() string {
	return stateNameRequestSent
}

func (s *requestSent) CanTransitionTo(st state) bool {
	return st.Name() == stateNamePresentationReceived ||
		st.Name() == stateNameProposalReceived ||
		st.Name() == StateNameAbandoned
}

func forwardInitial(md *metaData, v service.Version) stateAction {
	return func(messenger service.Messenger) error {
		return messenger.Send(md.Msg, md.MyDID, md.TheirDID, service.WithVersion(v))
	}
}

func (s *requestSent) Execute(md *metaData) (state, stateAction, error) {
	if md.Direction == outboundMessage {
		if s.V == SpecV3 {
			var req *RequestPresentationV3

			if err := md.Msg.Decode(&req); err != nil {
				return nil, nil, err
			}

			md.AckRequired = req.Body.WillConfirm

			return &noOp{}, forwardInitial(md, getDIDVersion(s.V)), nil
		}

		var req *RequestPresentationV2

		if err := md.Msg.Decode(&req); err != nil {
			return nil, nil, err
		}

		md.AckRequired = req.WillConfirm

		return &noOp{}, forwardInitial(md, getDIDVersion(s.V)), nil
	}

	if md.request == nil && md.requestV3 == nil {
		return nil, nil, errors.New("request was not provided")
	}

	if s.V == SpecV3 {
		md.AckRequired = md.requestV3.Body.WillConfirm
	} else {
		md.AckRequired = md.request.WillConfirm
	}

	return &noOp{}, func(messenger service.Messenger) error {
		if s.V == SpecV3 {
			md.requestV3.Type = RequestPresentationMsgTypeV3

			return messenger.ReplyToMsg(md.Msg, service.NewDIDCommMsgMap(md.requestV3), md.MyDID, md.TheirDID,
				service.WithVersion(getDIDVersion(s.V)),
			)
		}

		md.request.Type = RequestPresentationMsgTypeV2

		return messenger.ReplyToMsg(md.Msg, service.NewDIDCommMsgMap(md.request), md.MyDID, md.TheirDID,
			service.WithVersion(getDIDVersion(s.V)),
		)
	}, nil
}

func (s *requestSent) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

// presentationSent the Prover's state.
type presentationSent struct {
	V           string
	WillConfirm bool
}

func (s *presentationSent) Name() string {
	return stateNamePresentationSent
}

func (s *presentationSent) CanTransitionTo(st state) bool {
	return st.Name() == StateNameAbandoned ||
		st.Name() == StateNameDone
}

func (s *presentationSent) Execute(md *metaData) (state, stateAction, error) {
	if md.presentation == nil && md.presentationV3 == nil {
		return nil, nil, errors.New("presentation was not provided")
	}

	// creates the state's action
	action := func(messenger service.Messenger) error {
		if s.V == SpecV3 {
			// sets message type
			md.presentationV3.Type = PresentationMsgTypeV3

			return messenger.ReplyToMsg(md.Msg, service.NewDIDCommMsgMap(md.presentationV3), md.MyDID, md.TheirDID,
				service.WithVersion(getDIDVersion(s.V)),
			)
		}

		// sets message type
		md.presentation.Type = PresentationMsgTypeV2

		return messenger.ReplyToMsg(md.Msg, service.NewDIDCommMsgMap(md.presentation), md.MyDID, md.TheirDID,
			service.WithVersion(getDIDVersion(s.V)),
		)
	}

	if !s.WillConfirm {
		return &done{V: s.V}, action, nil
	}

	return &noOp{}, action, nil
}

func (s *presentationSent) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

// presentationReceived the Verifier's state.
type presentationReceived struct {
	V string
}

func (s *presentationReceived) Name() string {
	return stateNamePresentationReceived
}

func (s *presentationReceived) CanTransitionTo(st state) bool {
	return st.Name() == StateNameAbandoned ||
		st.Name() == StateNameDone
}

func (s *presentationReceived) Execute(md *metaData) (state, stateAction, error) {
	if !md.AckRequired {
		return &done{V: s.V}, zeroAction, nil
	}

	// creates the state's action
	action := func(messenger service.Messenger) error {
		if s.V == SpecV3 {
			return messenger.ReplyToMsg(md.Msg, service.NewDIDCommMsgMap(model.AckV2{
				Type:        AckMsgTypeV3,
				WebRedirect: md.properties[webRedirect],
				Body:        model.AckV2Body{},
			}), md.MyDID, md.TheirDID, service.WithVersion(getDIDVersion(s.V)))
		}

		return messenger.ReplyToMsg(md.Msg, service.NewDIDCommMsgMap(model.Ack{
			Type:        AckMsgTypeV2,
			Status:      "OK",
			WebRedirect: md.properties[webRedirect],
		}), md.MyDID, md.TheirDID, service.WithVersion(getDIDVersion(s.V)))
	}

	return &done{V: s.V}, action, nil
}

func (s *presentationReceived) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

// proposalSent the Prover's state.
type proposalSent struct {
	V string
}

func (s *proposalSent) Name() string {
	return stateNameProposalSent
}

func (s *proposalSent) CanTransitionTo(st state) bool {
	return st.Name() == stateNameRequestReceived ||
		st.Name() == StateNameAbandoned
}

func (s *proposalSent) Execute(md *metaData) (state, stateAction, error) {
	if md.Direction == outboundMessage {
		return &noOp{}, forwardInitial(md, getDIDVersion(s.V)), nil
	}

	if md.proposePresentation == nil && md.proposePresentationV3 == nil {
		return nil, nil, errors.New("propose-presentation was not provided")
	}

	return &noOp{}, func(messenger service.Messenger) error {
		if s.V == SpecV3 {
			md.proposePresentationV3.Type = ProposePresentationMsgTypeV3

			return messenger.ReplyToMsg(md.Msg, service.NewDIDCommMsgMap(md.proposePresentationV3), md.MyDID, md.TheirDID,
				service.WithVersion(getDIDVersion(s.V)),
			)
		}

		md.proposePresentation.Type = ProposePresentationMsgTypeV2

		return messenger.ReplyToMsg(md.Msg, service.NewDIDCommMsgMap(md.proposePresentation), md.MyDID, md.TheirDID,
			service.WithVersion(getDIDVersion(s.V)),
		)
	}, nil
}

func (s *proposalSent) Properties() map[string]interface{} {
	return map[string]interface{}{}
}

// proposalReceived the Verifier's state.
type proposalReceived struct {
	V string
}

func (s *proposalReceived) Name() string {
	return stateNameProposalReceived
}

func (s *proposalReceived) CanTransitionTo(st state) bool {
	return st.Name() == stateNameRequestSent ||
		st.Name() == StateNameAbandoned
}

func (s *proposalReceived) Execute(_ *metaData) (state, stateAction, error) {
	return &requestSent{V: s.V}, zeroAction, nil
}

func (s *proposalReceived) Properties() map[string]interface{} {
	return map[string]interface{}{}
}
