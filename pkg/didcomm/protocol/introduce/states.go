/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
)

const (
	codeNotApproved     = "not approved"
	codeRequestDeclined = "request declined"
	codeNoInvitation    = "no invitation"
	codeInternalError   = "internal error"
)

const (
	// common states
	stateNameNoop       = "noop"
	stateNameStart      = "start"
	stateNameAbandoning = "abandoning"
	stateNameDone       = "done"

	// introducer states
	stateNameArranging  = "arranging"
	stateNameDelivering = "delivering"
	stateNameConfirming = "confirming"

	// introducee states
	stateNameRequesting = "requesting"
	stateNameDeciding   = "deciding"
	stateNameWaiting    = "waiting"
)

// state action for network call
type stateAction func() error

// The introduce protocol's state.
type state interface {
	// Name of this state.
	Name() string
	// Whether this state allows transitioning into the next state.
	CanTransitionTo(next state) bool
	// Executes this state, returning a followup state to be immediately executed as well.
	// The 'noOp' state should be returned if the state has no followup.
	ExecuteInbound(messenger service.Messenger, msg *metaData) (state, stateAction, error)
	ExecuteOutbound(messenger service.Messenger, msg *metaData) (state, stateAction, error)
}

func zeroAction() error { return nil }

// noOp state
type noOp struct {
}

func (s *noOp) Name() string {
	return stateNameNoop
}

func (s *noOp) CanTransitionTo(_ state) bool {
	return false
}

func (s *noOp) ExecuteInbound(_ service.Messenger, _ *metaData) (state, stateAction, error) {
	return nil, nil, errors.New("cannot execute no-op")
}

func (s *noOp) ExecuteOutbound(_ service.Messenger, _ *metaData) (state, stateAction, error) {
	return nil, nil, errors.New("cannot execute no-op")
}

// start state
type start struct {
}

func (s *start) Name() string {
	return stateNameStart
}

func (s *start) CanTransitionTo(next state) bool {
	// Introducer can go to arranging or delivering state
	// Introducee can go to deciding
	switch next.Name() {
	case stateNameArranging, stateNameDeciding, stateNameRequesting, stateNameAbandoning:
		return true
	}

	return false
}

func (s *start) ExecuteInbound(_ service.Messenger, _ *metaData) (state, stateAction, error) {
	return nil, nil, errors.New("start: ExecuteInbound function is not supposed to be used")
}

func (s *start) ExecuteOutbound(_ service.Messenger, _ *metaData) (state, stateAction, error) {
	return nil, nil, errors.New("start: ExecuteOutbound function is not supposed to be used")
}

// done state
type done struct {
}

func (s *done) Name() string {
	return stateNameDone
}

func (s *done) CanTransitionTo(next state) bool {
	// done is the last state there is no possibility for the next state
	return false
}

func (s *done) ExecuteInbound(_ service.Messenger, _ *metaData) (state, stateAction, error) {
	return &noOp{}, zeroAction, nil
}

func (s *done) ExecuteOutbound(_ service.Messenger, _ *metaData) (state, stateAction, error) {
	return nil, nil, errors.New("done: ExecuteOutbound function is not supposed to be used")
}

// arranging state
type arranging struct {
}

func (s *arranging) Name() string {
	return stateNameArranging
}

func (s *arranging) CanTransitionTo(next state) bool {
	return next.Name() == stateNameArranging || next.Name() == stateNameDone ||
		next.Name() == stateNameAbandoning || next.Name() == stateNameDelivering
}

func isApproved(md *metaData) bool {
	for _, p := range md.participants {
		if !p.Approve {
			return false
		}
	}

	return true
}

func hasInvitation(md *metaData) bool {
	for _, p := range md.participants {
		if p.Invitation != nil {
			return true
		}
	}

	return false
}

func getMetaRecipients(md *metaData) []*Recipient {
	_recipients, ok := md.Msg.Metadata()[metaRecipients].([]interface{})
	if !ok {
		return nil
	}

	var recipients = make([]*Recipient, len(_recipients))

	for i, _recipient := range _recipients {
		recipient, ok := _recipient.(*Recipient)
		if !ok {
			// should never happen, otherwise, the protocol logic is broken
			panic("recipient type is wrong")
		}

		recipients[i] = recipient
	}

	return recipients
}

// CreateProposal creates a DIDCommMsgMap proposal
func CreateProposal(to *To) service.DIDCommMsgMap {
	return service.NewDIDCommMsgMap(Proposal{
		Type: ProposalMsgType,
		To:   to,
	})
}

func sendProposals(messenger service.Messenger, md *metaData) error {
	for _, recipient := range getMetaRecipients(md) {
		proposal := CreateProposal(recipient.To)
		proposal.Metadata()[metaPIID] = md.PIID
		copyMetadata(md.Msg, proposal)

		var err error
		if recipient.MyDID == "" && recipient.TheirDID == "" {
			err = messenger.ReplyTo(md.Msg.ID(), proposal)
		} else {
			err = messenger.Send(proposal, recipient.MyDID, recipient.TheirDID)
		}

		if err != nil {
			return fmt.Errorf("send proposals: %w", err)
		}
	}

	return nil
}

func (s *arranging) ExecuteInbound(messenger service.Messenger, md *metaData) (state, stateAction, error) {
	if md.Msg.Type() == RequestMsgType {
		return &noOp{}, func() error {
			return sendProposals(messenger, md)
		}, nil
	}

	if isSkipProposal(md) {
		if !isApproved(md) {
			return &abandoning{Code: codeNotApproved}, zeroAction, nil
		}

		return &delivering{}, zeroAction, nil
	}

	count := len(md.participants)
	if count != maxIntroducees || md.participants[count-1].TheirDID != md.TheirDID {
		return &noOp{}, zeroAction, nil
	}

	if !isApproved(md) {
		return &abandoning{Code: codeNotApproved}, zeroAction, nil
	}

	return &delivering{}, zeroAction, nil
}

func (s *arranging) ExecuteOutbound(messenger service.Messenger, md *metaData) (state, stateAction, error) {
	return &noOp{}, func() error { return messenger.Send(md.Msg, md.MyDID, md.TheirDID) }, nil
}

// delivering state
type delivering struct {
}

func (s *delivering) Name() string {
	return stateNameDelivering
}

func (s *delivering) CanTransitionTo(next state) bool {
	return next.Name() == stateNameConfirming || next.Name() == stateNameDone || next.Name() == stateNameAbandoning
}

func deliveringSkipInvitation(messenger service.Messenger, md *metaData) (state, stateAction, error) {
	thID, err := md.Msg.ThreadID()
	if err != nil {
		return nil, nil, err
	}

	return &done{}, func() error {
		inv, err := contextInvitation(md.Msg)
		if err != nil {
			return fmt.Errorf("context invitation: %w", err)
		}

		return messenger.ReplyToNested(thID, service.NewDIDCommMsgMap(inv), md.MyDID, md.TheirDID)
	}, nil
}

func (s *delivering) ExecuteInbound(messenger service.Messenger, md *metaData) (state, stateAction, error) {
	if isSkipProposal(md) {
		return deliveringSkipInvitation(messenger, md)
	}

	// edge case: no one shared the invitation
	if !hasInvitation(md) {
		return &abandoning{Code: codeNoInvitation}, zeroAction, nil
	}

	var inv *didexchange.Invitation

	var participants []*participant

	for _, participant := range md.participants {
		if participant.Invitation != nil && inv == nil {
			inv = participant.Invitation
		} else {
			participants = append(participants, participant)
		}
	}

	return &confirming{}, func() error {
		for _, p := range participants {
			err := messenger.ReplyToNested(p.ThreadID, service.NewDIDCommMsgMap(inv), p.MyDID, p.TheirDID)
			if err != nil {
				return fmt.Errorf("reply to nested: %w", err)
			}
		}

		return nil
	}, nil
}

func (s *delivering) ExecuteOutbound(_ service.Messenger, _ *metaData) (state, stateAction, error) {
	return nil, nil, errors.New("delivering: ExecuteOutbound function is not supposed to be used")
}

// confirming state
type confirming struct {
}

func (s *confirming) Name() string {
	return stateNameConfirming
}

func (s *confirming) CanTransitionTo(next state) bool {
	return next.Name() == stateNameDone || next.Name() == stateNameAbandoning
}

func (s *confirming) ExecuteInbound(messenger service.Messenger, md *metaData) (state, stateAction, error) {
	msgMap := service.NewDIDCommMsgMap(model.Ack{
		Type: AckMsgType,
	})

	var p *participant

	for _, participant := range md.participants {
		if participant.Invitation == nil {
			continue
		}

		p = participant

		break
	}

	return &done{}, func() error { return messenger.ReplyTo(p.MessageID, msgMap) }, nil
}

func (s *confirming) ExecuteOutbound(_ service.Messenger, _ *metaData) (state, stateAction, error) {
	return nil, nil, errors.New("confirming: ExecuteOutbound function is not supposed to be used")
}

// abandoning state
type abandoning struct {
	Code string
}

func (s *abandoning) Name() string {
	return stateNameAbandoning
}

func (s *abandoning) CanTransitionTo(next state) bool {
	return next.Name() == stateNameDone
}

func (s *abandoning) ExecuteInbound(messenger service.Messenger, md *metaData) (state, stateAction, error) {
	// if code is not provided it means we do not need to notify participants about it
	if s.Code == "" {
		return &done{}, zeroAction, nil
	}

	// In the protocol we might have a custom error.
	// 1. The introducer stop the protocol after receiving a request
	// 2. The introducee stop the protocol after receiving a proposal
	// When introducee stops the protocol we already send a Response with Approve=false. Code is "". Was ignore above.
	// Otherwise, we need to send a ProblemReport message.
	if errors.As(md.err, &customError{}) {
		// It is not possible to receive message without ID or threadID.
		// This error should never happen. If it happens it means that logic is broken.
		thID, err := md.Msg.ThreadID()
		if err != nil {
			return nil, nil, fmt.Errorf("threadID: %w", err)
		}

		// Sends a ProblemReport to the introducee.
		return &done{}, func() error {
			return messenger.ReplyToNested(thID, service.NewDIDCommMsgMap(model.ProblemReport{
				Type: ProblemReportMsgType,
				Description: model.Code{
					Code: codeRequestDeclined,
				}},
			), md.MyDID, md.TheirDID)
		}, nil
	}

	if len(md.participants) == 0 {
		md.participants = []*participant{{
			MyDID:    md.MyDID,
			TheirDID: md.TheirDID,
		}}
	}

	return &done{}, func() error {
		// notifies participants about error
		for _, recipient := range md.participants {
			// if code is codeNotApproved we need to ignore sending a ProblemReport
			// to the participant who rejected the introduction
			if s.Code == codeNotApproved && !recipient.Approve {
				continue
			}

			// sends a ProblemReport to the participant
			problem := service.NewDIDCommMsgMap(model.ProblemReport{
				Type: ProblemReportMsgType,
				Description: model.Code{
					Code: s.Code,
				},
			})

			if err := messenger.ReplyToNested(recipient.ThreadID, problem, recipient.MyDID, recipient.TheirDID); err != nil {
				return fmt.Errorf("send problem-report: %w", err)
			}
		}

		return nil
	}, nil
}

func (s *abandoning) ExecuteOutbound(_ service.Messenger, _ *metaData) (state, stateAction, error) {
	return nil, nil, errors.New("abandoning: ExecuteOutbound function is not supposed to be used")
}

// deciding state
type deciding struct {
}

func (s *deciding) Name() string {
	return stateNameDeciding
}

func (s *deciding) CanTransitionTo(next state) bool {
	return next.Name() == stateNameWaiting || next.Name() == stateNameDone || next.Name() == stateNameAbandoning
}

func (s *deciding) ExecuteInbound(messenger service.Messenger, md *metaData) (state, stateAction, error) {
	var st state = &waiting{}
	if md.rejected {
		st = &abandoning{}
	}

	return st, func() error {
		inv, err := contextInvitation(md.Msg)
		if err != nil {
			return fmt.Errorf("context invitation: %w", err)
		}

		return messenger.ReplyTo(md.Msg.ID(), service.NewDIDCommMsgMap(Response{
			Type:       ResponseMsgType,
			Invitation: inv,
			Approve:    !md.rejected,
		}))
	}, nil
}

func (s *deciding) ExecuteOutbound(_ service.Messenger, _ *metaData) (state, stateAction, error) {
	return nil, nil, errors.New("deciding: ExecuteOutbound function is not supposed to be used")
}

// waiting state
type waiting struct {
}

func (s *waiting) Name() string {
	return stateNameWaiting
}

func (s *waiting) CanTransitionTo(next state) bool {
	return next.Name() == stateNameDone || next.Name() == stateNameAbandoning
}

func (s *waiting) ExecuteInbound(_ service.Messenger, _ *metaData) (state, stateAction, error) {
	return &noOp{}, zeroAction, nil
}

func (s *waiting) ExecuteOutbound(_ service.Messenger, _ *metaData) (state, stateAction, error) {
	return nil, nil, errors.New("waiting: ExecuteOutbound function is not supposed to be used")
}

// requesting state
type requesting struct {
}

func (s *requesting) Name() string {
	return stateNameRequesting
}

func (s *requesting) CanTransitionTo(next state) bool {
	return next.Name() == stateNameDeciding || next.Name() == stateNameAbandoning || next.Name() == stateNameDone
}

func (s *requesting) ExecuteInbound(_ service.Messenger, _ *metaData) (state, stateAction, error) {
	return nil, nil, errors.New("requesting: ExecuteInbound function is not supposed to be used")
}

func (s *requesting) ExecuteOutbound(messenger service.Messenger, md *metaData) (state, stateAction, error) {
	return &noOp{}, func() error {
		return messenger.Send(md.Msg, md.MyDID, md.TheirDID)
	}, nil
}
