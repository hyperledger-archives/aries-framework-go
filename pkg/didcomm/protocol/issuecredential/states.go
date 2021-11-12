/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

const (
	// common states.
	stateNameStart      = "start"
	stateNameAbandoning = "abandoning"
	stateNameDone       = "done"
	stateNameNoop       = "noop"

	// states for Issuer.
	stateNameProposalReceived = "proposal-received"
	stateNameOfferSent        = "offer-sent"
	stateNameRequestReceived  = "request-received"
	stateNameCredentialIssued = "credential-issued"

	// states for Holder.
	stateNameProposalSent       = "proposal-sent"
	stateNameOfferReceived      = "offer-received"
	stateNameRequestSent        = "request-sent"
	stateNameCredentialReceived = "credential-received"
)

const (
	codeRejectedError = "rejected"
	codeInternalError = "internal"
)

// state action for network call.
type stateAction func(messenger service.Messenger) error

// the protocol's state.
type state interface {
	// Name of this state.
	Name() string
	// CanTransitionTo Whether this state allows transitioning into the next state.
	CanTransitionTo(next state) bool
	// ExecuteInbound this state, returning a followup state to be immediately executed as well.
	// The 'noOp' state should be returned if the state has no followup.
	ExecuteInbound(msg *MetaData) (state, stateAction, error)
	ExecuteOutbound(msg *MetaData) (state, stateAction, error)
}

// represents zero state's action.
func zeroAction(service.Messenger) error { return nil }

// noOp state.
type noOp struct{}

func (s *noOp) Name() string {
	return stateNameNoop
}

func (s *noOp) CanTransitionTo(_ state) bool {
	return false
}

func (s *noOp) ExecuteInbound(_ *MetaData) (state, stateAction, error) {
	return nil, nil, errors.New("cannot execute no-op")
}

func (s *noOp) ExecuteOutbound(_ *MetaData) (state, stateAction, error) {
	return nil, nil, errors.New("cannot execute no-op")
}

// start state.
type start struct{}

func (s *start) Name() string {
	return stateNameStart
}

func (s *start) CanTransitionTo(st state) bool {
	switch st.Name() {
	// Issuer.
	case stateNameProposalReceived, stateNameOfferSent, stateNameRequestReceived:
		return true
	// Holder.
	case stateNameProposalSent, stateNameOfferReceived, stateNameRequestSent:
		return true
	}

	return false
}

func (s *start) ExecuteInbound(_ *MetaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *start) ExecuteOutbound(_ *MetaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// abandoning state.
type abandoning struct {
	V    string
	Code string
}

func (s *abandoning) Name() string {
	return stateNameAbandoning
}

func (s *abandoning) CanTransitionTo(st state) bool {
	return st.Name() == stateNameDone
}

func (s *abandoning) ExecuteInbound(md *MetaData) (state, stateAction, error) {
	// if code is not provided it means we do not need to notify the another agent.
	// if we received ProblemReport message no need to answer.
	if s.Code == "" || md.Msg.Type() == ProblemReportMsgTypeV2 || md.Msg.Type() == ProblemReportMsgTypeV3 {
		return &done{}, zeroAction, nil
	}

	code := model.Code{Code: s.Code}

	// if the protocol was stopped by the user we will set the rejected error code.
	if errors.As(md.err, &customError{}) {
		code = model.Code{Code: codeRejectedError}
	}

	thID, err := md.Msg.ThreadID()
	if err != nil {
		return nil, nil, fmt.Errorf("threadID: %w", err)
	}

	return &done{}, func(messenger service.Messenger) error {
		if s.V == SpecV3 {
			return messenger.ReplyToNested(service.NewDIDCommMsgMap(&model.ProblemReportV2{
				Type: ProblemReportMsgTypeV3,
				Body: model.ProblemReportV2Body{Code: code.Code},
			}), &service.NestedReplyOpts{ThreadID: thID, MyDID: md.MyDID, TheirDID: md.TheirDID, V: getDIDVersion(s.V)})
		}

		return messenger.ReplyToNested(service.NewDIDCommMsgMap(&model.ProblemReport{
			Type:        ProblemReportMsgTypeV2,
			Description: code,
		}), &service.NestedReplyOpts{ThreadID: thID, MyDID: md.MyDID, TheirDID: md.TheirDID, V: getDIDVersion(s.V)})
	}, nil
}

func (s *abandoning) ExecuteOutbound(_ *MetaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// done state.
type done struct {
	V string
}

func (s *done) Name() string {
	return stateNameDone
}

func (s *done) CanTransitionTo(_ state) bool {
	return false
}

func (s *done) ExecuteInbound(_ *MetaData) (state, stateAction, error) {
	return &noOp{}, zeroAction, nil
}

func (s *done) ExecuteOutbound(_ *MetaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// proposalReceived the Issuer's state.
type proposalReceived struct {
	V string
}

func (s *proposalReceived) Name() string {
	return stateNameProposalReceived
}

func (s *proposalReceived) CanTransitionTo(st state) bool {
	return st.Name() == stateNameOfferSent || st.Name() == stateNameAbandoning
}

func (s *proposalReceived) ExecuteInbound(_ *MetaData) (state, stateAction, error) {
	return &offerSent{V: s.V}, zeroAction, nil
}

func (s *proposalReceived) ExecuteOutbound(_ *MetaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// offerSent the Issuer's state.
type offerSent struct {
	V string
}

func (s *offerSent) Name() string {
	return stateNameOfferSent
}

func (s *offerSent) CanTransitionTo(st state) bool {
	return st.Name() == stateNameProposalReceived ||
		st.Name() == stateNameRequestReceived ||
		st.Name() == stateNameAbandoning
}

func (s *offerSent) ExecuteInbound(md *MetaData) (state, stateAction, error) {
	if md.offerCredential == nil && md.offerCredentialV3 == nil {
		return nil, nil, errors.New("offer credential was not provided")
	}

	// creates the state's action.
	action := func(messenger service.Messenger) error {
		if s.V == SpecV3 {
			// sets message type
			md.offerCredentialV3.Type = OfferCredentialMsgTypeV3

			return messenger.ReplyToMsg(md.Msg, service.NewDIDCommMsgMap(md.offerCredentialV3), md.MyDID, md.TheirDID,
				service.WithVersion(getDIDVersion(s.V)))
		}

		// sets message type.
		md.offerCredential.Type = OfferCredentialMsgTypeV2

		return messenger.ReplyToMsg(md.Msg, service.NewDIDCommMsgMap(md.offerCredential), md.MyDID, md.TheirDID,
			service.WithVersion(getDIDVersion(s.V)))
	}

	return &noOp{}, action, nil
}

func (s *offerSent) ExecuteOutbound(md *MetaData) (state, stateAction, error) {
	// creates the state's action.
	action := func(messenger service.Messenger) error {
		return messenger.Send(md.Msg, md.MyDID, md.TheirDID, service.WithVersion(getDIDVersion(s.V)))
	}

	return &noOp{}, action, nil
}

// requestReceived the Issuer's state.
type requestReceived struct {
	V string
}

func (s *requestReceived) Name() string {
	return stateNameRequestReceived
}

func (s *requestReceived) CanTransitionTo(st state) bool {
	return st.Name() == stateNameCredentialIssued || st.Name() == stateNameAbandoning
}

func (s *requestReceived) ExecuteInbound(md *MetaData) (state, stateAction, error) {
	if md.issueCredential == nil && md.issueCredentialV3 == nil {
		return nil, nil, errors.New("issue credential was not provided")
	}

	// creates the state's action
	action := func(messenger service.Messenger) error {
		if s.V == SpecV3 {
			// sets message type
			md.issueCredentialV3.Type = IssueCredentialMsgTypeV3

			return messenger.ReplyToMsg(md.Msg, service.NewDIDCommMsgMap(md.issueCredentialV3), md.MyDID, md.TheirDID,
				service.WithVersion(getDIDVersion(s.V)))
		}

		// sets message type
		md.issueCredential.Type = IssueCredentialMsgTypeV2

		return messenger.ReplyToMsg(md.Msg, service.NewDIDCommMsgMap(md.issueCredential), md.MyDID, md.TheirDID,
			service.WithVersion(getDIDVersion(s.V)))
	}

	return &credentialIssued{}, action, nil
}

func (s *requestReceived) ExecuteOutbound(_ *MetaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// credentialIssued the Issuer's state.
type credentialIssued struct {
	V string
}

func (s *credentialIssued) Name() string {
	return stateNameCredentialIssued
}

func (s *credentialIssued) CanTransitionTo(st state) bool {
	return st.Name() == stateNameDone || st.Name() == stateNameAbandoning
}

func (s *credentialIssued) ExecuteInbound(_ *MetaData) (state, stateAction, error) {
	return &noOp{}, zeroAction, nil
}

func (s *credentialIssued) ExecuteOutbound(_ *MetaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// proposalSent the Holder's state.
type proposalSent struct {
	V string
}

func (s *proposalSent) Name() string {
	return stateNameProposalSent
}

func (s *proposalSent) CanTransitionTo(st state) bool {
	return st.Name() == stateNameOfferReceived || st.Name() == stateNameAbandoning
}

func (s *proposalSent) ExecuteInbound(md *MetaData) (state, stateAction, error) {
	if md.proposeCredential == nil && md.proposeCredentialV3 == nil {
		return nil, nil, errors.New("propose credential was not provided")
	}

	// creates the state's action
	action := func(messenger service.Messenger) error {
		if s.V == SpecV3 {
			// sets message type
			md.proposeCredentialV3.Type = ProposeCredentialMsgTypeV3

			return messenger.ReplyToMsg(md.Msg, service.NewDIDCommMsgMap(md.proposeCredentialV3), md.MyDID, md.TheirDID,
				service.WithVersion(getDIDVersion(s.V)))
		}

		// sets message type
		md.proposeCredential.Type = ProposeCredentialMsgTypeV2

		return messenger.ReplyToMsg(md.Msg, service.NewDIDCommMsgMap(md.proposeCredential), md.MyDID, md.TheirDID,
			service.WithVersion(getDIDVersion(s.V)))
	}

	return &noOp{}, action, nil
}

func (s *proposalSent) ExecuteOutbound(md *MetaData) (state, stateAction, error) {
	// creates the state's action
	action := func(messenger service.Messenger) error {
		return messenger.Send(md.Msg, md.MyDID, md.TheirDID, service.WithVersion(getDIDVersion(s.V)))
	}

	return &noOp{}, action, nil
}

// offerReceived the Holder's state.
type offerReceived struct {
	V string
}

func (s *offerReceived) Name() string {
	return stateNameOfferReceived
}

func (s *offerReceived) CanTransitionTo(st state) bool {
	return st.Name() == stateNameProposalSent ||
		st.Name() == stateNameRequestSent ||
		st.Name() == stateNameAbandoning
}

func (s *offerReceived) ExecuteInbound(md *MetaData) (state, stateAction, error) {
	// sends propose credential if it was provided
	if md.proposeCredential != nil || md.proposeCredentialV3 != nil {
		return &proposalSent{V: s.V}, zeroAction, nil
	}

	var action func(messenger service.Messenger) error

	if s.V == SpecV3 { //nolint: nestif
		offer := OfferCredentialV3{}
		if err := md.Msg.Decode(&offer); err != nil {
			return nil, nil, fmt.Errorf("decode: %w", err)
		}

		response := &RequestCredentialV3{
			Type: RequestCredentialMsgTypeV3,
			ID:   offer.ID,
			Body: RequestCredentialV3Body{
				GoalCode: offer.Body.GoalCode,
				Comment:  offer.Body.Comment,
			},
			Attachments: offer.Attachments,
		}

		if md.RequestCredentialV3() != nil {
			response = md.RequestCredentialV3()
			response.Type = RequestCredentialMsgTypeV3
		}

		// creates the state's action
		action = func(messenger service.Messenger) error {
			return messenger.ReplyToMsg(md.Msg, service.NewDIDCommMsgMap(response), md.MyDID, md.TheirDID,
				service.WithVersion(getDIDVersion(s.V)))
		}
	} else {
		offer := OfferCredential{}
		if err := md.Msg.Decode(&offer); err != nil {
			return nil, nil, fmt.Errorf("decode: %w", err)
		}

		response := &RequestCredential{
			Type:           RequestCredentialMsgTypeV2,
			Formats:        offer.Formats,
			RequestsAttach: offer.OffersAttach,
		}

		if md.RequestCredential() != nil {
			response = md.RequestCredential()
			response.Type = RequestCredentialMsgTypeV2
		}

		// creates the state's action
		action = func(messenger service.Messenger) error {
			return messenger.ReplyToMsg(md.Msg, service.NewDIDCommMsgMap(response), md.MyDID, md.TheirDID,
				service.WithVersion(getDIDVersion(s.V)))
		}
	}

	return &requestSent{}, action, nil
}

func (s *offerReceived) ExecuteOutbound(_ *MetaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// requestSent the Holder's state.
type requestSent struct {
	V string
}

func (s *requestSent) Name() string {
	return stateNameRequestSent
}

func (s *requestSent) CanTransitionTo(st state) bool {
	return st.Name() == stateNameCredentialReceived || st.Name() == stateNameAbandoning
}

func (s *requestSent) ExecuteInbound(_ *MetaData) (state, stateAction, error) {
	return &noOp{}, zeroAction, nil
}

func (s *requestSent) ExecuteOutbound(md *MetaData) (state, stateAction, error) {
	// creates the state's action
	action := func(messenger service.Messenger) error {
		return messenger.Send(md.Msg, md.MyDID, md.TheirDID, service.WithVersion(getDIDVersion(s.V)))
	}

	return &noOp{}, action, nil
}

// credentialReceived state.
type credentialReceived struct {
	V string
}

func (s *credentialReceived) Name() string {
	return stateNameCredentialReceived
}

func (s *credentialReceived) CanTransitionTo(st state) bool {
	return st.Name() == stateNameDone || st.Name() == stateNameAbandoning
}

func (s *credentialReceived) ExecuteInbound(md *MetaData) (state, stateAction, error) {
	// creates the state's action
	action := func(messenger service.Messenger) error {
		if s.V == SpecV3 {
			return messenger.ReplyToMsg(md.Msg, service.NewDIDCommMsgMap(model.AckV2{
				Type: AckMsgTypeV3,
				Body: model.AckV2Body{Status: "OK"},
			}), md.MyDID, md.TheirDID, service.WithVersion(getDIDVersion(s.V)))
		}

		return messenger.ReplyToMsg(md.Msg, service.NewDIDCommMsgMap(model.Ack{
			Type:   AckMsgTypeV2,
			Status: "OK",
		}), md.MyDID, md.TheirDID, service.WithVersion(getDIDVersion(s.V)))
	}

	return &done{}, action, nil
}

func (s *credentialReceived) ExecuteOutbound(_ *MetaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}
