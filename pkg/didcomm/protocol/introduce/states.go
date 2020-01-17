/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
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

// The introduce protocol's state.
type state interface {
	// Name of this state.
	Name() string
	// Whether this state allows transitioning into the next state.
	CanTransitionTo(next state) bool
	// Executes this state, returning a followup state to be immediately executed as well.
	// The 'noOp' state should be returned if the state has no followup.
	ExecuteInbound(dis dispatcher.Outbound, msg *metaData) (followup state, err error)
	ExecuteOutbound(dis dispatcher.Outbound, msg *metaData) (followup state, err error)
}

// noOp state
type noOp struct {
}

func (s *noOp) Name() string {
	return stateNameNoop
}

func (s *noOp) CanTransitionTo(_ state) bool {
	return false
}

func (s *noOp) ExecuteInbound(_ dispatcher.Outbound, _ *metaData) (state, error) {
	return nil, errors.New("cannot execute no-op")
}

func (s *noOp) ExecuteOutbound(_ dispatcher.Outbound, _ *metaData) (state, error) {
	return nil, errors.New("cannot execute no-op")
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

func (s *start) ExecuteInbound(_ dispatcher.Outbound, _ *metaData) (state, error) {
	return nil, errors.New("start ExecuteInbound: not implemented yet")
}

func (s *start) ExecuteOutbound(_ dispatcher.Outbound, _ *metaData) (state, error) {
	return nil, errors.New("start ExecuteOutbound: not implemented yet")
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

func (s *done) ExecuteInbound(_ dispatcher.Outbound, _ *metaData) (state, error) {
	return &noOp{}, nil
}

func (s *done) ExecuteOutbound(_ dispatcher.Outbound, _ *metaData) (state, error) {
	return nil, errors.New("done ExecuteOutbound: not implemented yet")
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

func (s *arranging) ExecuteInbound(dis dispatcher.Outbound, m *metaData) (state, error) {
	// after receiving a response we need to determine whether it is skip proposal or no
	// if this is skip proposal we do not need to send a proposal to another introducee
	// we just simply go to Delivering state
	if m.Msg.Type() == ResponseMsgType && isSkipProposal(m) {
		return &delivering{}, nil
	}

	if approve, ok := getApproveFromMsg(m.Msg); ok && !approve {
		return &abandoning{}, nil
	}

	var recipient *Recipient

	// sends Proposal according to the WaitCount
	if m.WaitCount == initialWaitCount {
		recipient = m.Recipients[0]
	} else {
		recipient = m.Recipients[1]
	}

	return &noOp{}, dis.SendToDID(&Proposal{
		Type:   ProposalMsgType,
		ID:     uuid.New().String(),
		To:     recipient.To,
		Thread: &decorator.Thread{ID: m.ThreadID},
	}, recipient.MyDID, recipient.TheirDID)
}

func (s *arranging) ExecuteOutbound(dis dispatcher.Outbound, m *metaData) (state, error) {
	var proposal = Proposal{}
	if err := m.Msg.Decode(&proposal); err != nil {
		return nil, fmt.Errorf("outbound unmarshal: %w", err)
	}

	if err := dis.SendToDID(&proposal, m.myDID, m.theirDID); err != nil {
		return nil, fmt.Errorf("arranging: SendToDID: %w", err)
	}

	return &noOp{}, nil
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

// toDestIDx returns destination index based on introducee index
func toDestIDx(idx int) int {
	if idx == 0 {
		return 1
	}

	return 0
}

func getApproveFromMsg(msg service.DIDCommMsg) (bool, bool) {
	if msg.Type() != ResponseMsgType {
		return false, false
	}

	r := Response{}

	if err := msg.Decode(&r); err != nil {
		return false, false
	}

	return r.Approve, true
}

func sendProblemReport(dis dispatcher.Outbound, m *metaData, recipients []*Recipient) (state, error) {
	problem := &model.ProblemReport{
		Type: ProblemReportMsgType,
		ID:   m.ThreadID,
	}

	for _, recipient := range recipients {
		if err := dis.SendToDID(problem, recipient.MyDID, recipient.TheirDID); err != nil {
			return nil, fmt.Errorf("send problem-report: %w", err)
		}
	}

	return &done{}, nil
}

func deliveringSkipInvitation(dis dispatcher.Outbound, m *metaData, recipients []*Recipient) (state, error) {
	// for skip proposal, we always have only one recipient e.g recipients[0]
	inv := m.dependency.Invitation()
	inv.Thread = &decorator.Thread{PID: m.ThreadID}

	err := dis.SendToDID(inv, recipients[0].MyDID, recipients[0].TheirDID)
	if err != nil {
		return nil, fmt.Errorf("send inbound invitation (skip): %w", err)
	}

	return &done{}, nil
}

func (s *delivering) ExecuteInbound(dis dispatcher.Outbound, m *metaData) (state, error) {
	if approve, ok := getApproveFromMsg(m.Msg); ok && !approve {
		return &abandoning{}, nil
	}

	if isSkipProposal(m) {
		return deliveringSkipInvitation(dis, m, m.Recipients)
	}

	// edge case: no one shared the invitation
	if m.Invitation == nil {
		return &abandoning{}, nil
	}

	m.Invitation.Thread = &decorator.Thread{PID: m.ThreadID}

	recipient := m.Recipients[toDestIDx(m.IntroduceeIndex)]

	if err := dis.SendToDID(m.Invitation, recipient.MyDID, recipient.TheirDID); err != nil {
		return nil, fmt.Errorf("send inbound invitation: %w", err)
	}

	return &confirming{}, nil
}

func (s *delivering) ExecuteOutbound(_ dispatcher.Outbound, _ *metaData) (state, error) {
	return nil, errors.New("delivering ExecuteOutbound: not implemented yet")
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

func (s *confirming) ExecuteInbound(dis dispatcher.Outbound, m *metaData) (state, error) {
	recipient := m.Recipients[m.IntroduceeIndex]

	err := dis.SendToDID(&model.Ack{
		Type:   AckMsgType,
		ID:     uuid.New().String(),
		Thread: &decorator.Thread{ID: m.ThreadID},
	}, recipient.MyDID, recipient.TheirDID)

	if err != nil {
		return nil, fmt.Errorf("send ack: %w", err)
	}

	return &done{}, nil
}

func (s *confirming) ExecuteOutbound(_ dispatcher.Outbound, _ *metaData) (state, error) {
	return nil, errors.New("confirming ExecuteOutbound: not implemented yet")
}

// abandoning state
type abandoning struct {
}

func (s *abandoning) Name() string {
	return stateNameAbandoning
}

func (s *abandoning) CanTransitionTo(next state) bool {
	return next.Name() == stateNameDone
}

func fillRecipient(recipients []*Recipient, m *metaData) []*Recipient {
	// for the first recipient, we may do not have a destination
	// in that case, we need to get destination from the inbound message
	// NOTE: it happens after receiving the Request message.
	if len(recipients) == 0 {
		return append(recipients, &Recipient{
			MyDID:    m.myDID,
			TheirDID: m.theirDID,
		})
	}

	if recipients[0].MyDID == "" {
		recipients[0].MyDID = m.myDID
	}

	if recipients[0].TheirDID == "" {
		recipients[0].TheirDID = m.theirDID
	}

	return recipients
}

func (s *abandoning) ExecuteInbound(dis dispatcher.Outbound, m *metaData) (state, error) {
	var recipients []*Recipient

	if m.Msg.Type() == RequestMsgType {
		recipients = fillRecipient(nil, m)
	}

	if m.Msg.Type() == ResponseMsgType {
		recipients = fillRecipient(m.Recipients, m)
	}

	if approve, ok := getApproveFromMsg(m.Msg); ok && !approve {
		if m.WaitCount == 1 {
			return &done{}, nil
		}
		// if we receive the second Response with Approve=false
		// report-problem should be sent only to the first introducee
		recipients = recipients[:1]
	}

	return sendProblemReport(dis, m, recipients)
}

func (s *abandoning) ExecuteOutbound(_ dispatcher.Outbound, _ *metaData) (state, error) {
	return nil, errors.New("abandoning ExecuteOutbound: not implemented yet")
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

func (s *deciding) ExecuteInbound(dis dispatcher.Outbound, m *metaData) (state, error) {
	var inv *didexchange.Invitation

	if m.dependency != nil {
		inv = m.dependency.Invitation()
	}

	var st state = &waiting{}
	if m.disapprove {
		st = &abandoning{}
	}

	return st, dis.SendToDID(&Response{
		Type:       ResponseMsgType,
		ID:         uuid.New().String(),
		Thread:     &decorator.Thread{ID: m.ThreadID},
		Invitation: inv,
		Approve:    !m.disapprove,
	}, m.myDID, m.theirDID)
}

func (s *deciding) ExecuteOutbound(_ dispatcher.Outbound, _ *metaData) (state, error) {
	return nil, errors.New("deciding ExecuteOutbound: not implemented yet")
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

func (s *waiting) ExecuteInbound(_ dispatcher.Outbound, _ *metaData) (state, error) {
	return &noOp{}, nil
}

func (s *waiting) ExecuteOutbound(_ dispatcher.Outbound, _ *metaData) (state, error) {
	return nil, errors.New("waiting ExecuteOutbound: not implemented yet")
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

func (s *requesting) ExecuteInbound(_ dispatcher.Outbound, _ *metaData) (state, error) {
	return nil, errors.New("requesting ExecuteInbound: not implemented yet")
}

func (s *requesting) ExecuteOutbound(dis dispatcher.Outbound, m *metaData) (state, error) {
	var req = Request{}

	if err := m.Msg.Decode(&req); err != nil {
		return nil, fmt.Errorf("requesting outbound unmarshal: %w", err)
	}

	return &noOp{}, dis.SendToDID(&req, m.myDID, m.theirDID)
}
