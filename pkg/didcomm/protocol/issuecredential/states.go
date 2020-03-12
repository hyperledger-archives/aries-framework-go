/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
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

const (
	codeRejectedError = "rejected"
	codeInternalError = "internal"
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
	switch st.Name() {
	// Issuer
	case stateNameProposalReceived, stateNameOfferSent, stateNameRequestReceived:
		return true
	// Holder
	case stateNameProposalSent, stateNameOfferReceived, stateNameRequestSent:
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

// proposalReceived the Issuer's state
type proposalReceived struct{}

func (s *proposalReceived) Name() string {
	return stateNameProposalReceived
}

func (s *proposalReceived) CanTransitionTo(st state) bool {
	return st.Name() == stateNameOfferSent || st.Name() == stateNameAbandoning
}

func (s *proposalReceived) ExecuteInbound(md *metaData) (state, stateAction, error) {
	if md.offerCredential == nil {
		return nil, nil, errors.New("offer credential was not provided")
	}

	// creates the state's action
	action := func(messenger service.Messenger) error {
		// sets message type
		md.offerCredential.Type = OfferCredentialMsgType
		return messenger.ReplyTo(md.Msg.ID(), service.NewDIDCommMsgMap(md.offerCredential))
	}

	return &noOp{}, action, nil
}

func (s *proposalReceived) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// offerSent the Issuer's state
type offerSent struct{}

func (s *offerSent) Name() string {
	return stateNameOfferSent
}

func (s *offerSent) CanTransitionTo(st state) bool {
	return st.Name() == stateNameProposalReceived ||
		st.Name() == stateNameRequestReceived ||
		st.Name() == stateNameAbandoning
}

func (s *offerSent) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteInbound is not implemented yet", s.Name())
}

func (s *offerSent) ExecuteOutbound(md *metaData) (state, stateAction, error) {
	// creates the state's action
	action := func(messenger service.Messenger) error {
		return messenger.Send(md.Msg, md.MyDID, md.TheirDID)
	}

	return &noOp{}, action, nil
}

// requestReceived the Issuer's state
type requestReceived struct{}

func (s *requestReceived) Name() string {
	return stateNameRequestReceived
}

func (s *requestReceived) CanTransitionTo(st state) bool {
	return st.Name() == stateNameCredentialIssued || st.Name() == stateNameAbandoning
}

func (s *requestReceived) ExecuteInbound(md *metaData) (state, stateAction, error) {
	if md.issueCredential == nil {
		return nil, nil, errors.New("issue credential was not provided")
	}

	// creates the state's action
	action := func(messenger service.Messenger) error {
		// sets message type
		md.issueCredential.Type = IssueCredentialMsgType
		return messenger.ReplyTo(md.Msg.ID(), service.NewDIDCommMsgMap(md.issueCredential))
	}

	return &credentialIssued{}, action, nil
}

func (s *requestReceived) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// credentialIssued the Issuer's state
type credentialIssued struct{}

func (s *credentialIssued) Name() string {
	return stateNameCredentialIssued
}

func (s *credentialIssued) CanTransitionTo(st state) bool {
	return st.Name() == stateNameDone || st.Name() == stateNameAbandoning
}

func (s *credentialIssued) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return &noOp{}, zeroAction, nil
}

func (s *credentialIssued) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// proposalSent the Holder's state
type proposalSent struct{}

func (s *proposalSent) Name() string {
	return stateNameProposalSent
}

func (s *proposalSent) CanTransitionTo(st state) bool {
	return st.Name() == stateNameOfferReceived || st.Name() == stateNameAbandoning
}

func (s *proposalSent) ExecuteInbound(md *metaData) (state, stateAction, error) {
	if md.proposeCredential == nil {
		return nil, nil, errors.New("propose credential was not provided")
	}

	// creates the state's action
	action := func(messenger service.Messenger) error {
		// sets message type
		md.proposeCredential.Type = ProposeCredentialMsgType
		return messenger.ReplyTo(md.Msg.ID(), service.NewDIDCommMsgMap(md.proposeCredential))
	}

	return &noOp{}, action, nil
}

func (s *proposalSent) ExecuteOutbound(md *metaData) (state, stateAction, error) {
	// creates the state's action
	action := func(messenger service.Messenger) error {
		return messenger.Send(md.Msg, md.MyDID, md.TheirDID)
	}

	return &noOp{}, action, nil
}

// offerReceived the Holder's state
type offerReceived struct{}

func (s *offerReceived) Name() string {
	return stateNameOfferReceived
}

func (s *offerReceived) CanTransitionTo(st state) bool {
	return st.Name() == stateNameProposalSent ||
		st.Name() == stateNameRequestSent ||
		st.Name() == stateNameAbandoning
}

func (s *offerReceived) ExecuteInbound(md *metaData) (state, stateAction, error) {
	// sends propose credential if it was provided
	if md.proposeCredential != nil {
		return &proposalSent{}, zeroAction, nil
	}

	var offer = OfferCredential{}
	if err := md.Msg.Decode(&offer); err != nil {
		return nil, nil, fmt.Errorf("decode: %w", err)
	}

	// creates the state's action
	action := func(messenger service.Messenger) error {
		return messenger.ReplyTo(md.Msg.ID(), service.NewDIDCommMsgMap(RequestCredential{
			Type:           RequestCredentialMsgType,
			RequestsAttach: offer.OffersAttach,
		}))
	}

	return &requestSent{}, action, nil
}

func (s *offerReceived) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}

// requestSent the Holder's state
type requestSent struct{}

func (s *requestSent) Name() string {
	return stateNameRequestSent
}

func (s *requestSent) CanTransitionTo(st state) bool {
	return st.Name() == stateNameCredentialReceived || st.Name() == stateNameAbandoning
}

func (s *requestSent) ExecuteInbound(_ *metaData) (state, stateAction, error) {
	return &noOp{}, zeroAction, nil
}

func (s *requestSent) ExecuteOutbound(md *metaData) (state, stateAction, error) {
	// creates the state's action
	action := func(messenger service.Messenger) error {
		return messenger.Send(md.Msg, md.MyDID, md.TheirDID)
	}

	return &noOp{}, action, nil
}

// credentialReceived state
type credentialReceived struct{}

func (s *credentialReceived) Name() string {
	return stateNameCredentialReceived
}

func (s *credentialReceived) CanTransitionTo(st state) bool {
	return st.Name() == stateNameDone || st.Name() == stateNameAbandoning
}

func toVerifiableCredentials(attachments []decorator.Attachment) ([]*verifiable.Credential, error) {
	var credentials []*verifiable.Credential

	// TODO: Currently, it supports only JSON payload. We need to add support for links and base64 as well. [Issue 1455]
	for i := range attachments {
		rawVC, err := json.Marshal(attachments[i].Data.JSON)
		if err != nil {
			return nil, fmt.Errorf("marshal: %w", err)
		}

		vc, _, err := verifiable.NewCredential(rawVC)
		if err != nil {
			return nil, fmt.Errorf("new credential: %w", err)
		}

		credentials = append(credentials, vc)
	}

	return credentials, nil
}

func (s *credentialReceived) ExecuteInbound(md *metaData) (state, stateAction, error) {
	var credential = IssueCredential{}

	err := md.Msg.Decode(&credential)
	if err != nil {
		return nil, nil, fmt.Errorf("decode: %w", err)
	}

	md.credentials, err = toVerifiableCredentials(credential.CredentialsAttach)
	if err != nil {
		return nil, nil, fmt.Errorf("to verifiable credentials: %w", err)
	}

	if len(md.credentials) == 0 {
		return nil, nil, errors.New("credentials were not provided")
	}

	// creates the state's action
	action := func(messenger service.Messenger) error {
		return messenger.ReplyTo(md.Msg.ID(), service.NewDIDCommMsgMap(model.Ack{
			Type: AckMsgType,
		}))
	}

	return &done{}, action, nil
}

func (s *credentialReceived) ExecuteOutbound(_ *metaData) (state, stateAction, error) {
	return nil, nil, fmt.Errorf("%s: ExecuteOutbound is not implemented yet", s.Name())
}
