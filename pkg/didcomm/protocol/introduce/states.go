/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"encoding/json"
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
	stateNameNoop  = "noop"
	stateNameStart = "start"
	stateNameDone  = "done"

	// introducer states
	stateNameArranging  = "arranging"
	stateNameDelivering = "delivering"
	stateNameConfirming = "confirming"
	stateNameAbandoning = "abandoning"

	// introducee states
	stateNameDeciding = "deciding"
	stateNameWaiting  = "waiting"
)

// nolint: gochecknoglobals
var getInboundDestination = func() *service.Destination {
	// TODO: need to get real destination and key
	return &service.Destination{}
}

type internalContext struct {
	dispatcher.Outbound
	SendInvitation func(inv *didexchange.Invitation, dest *service.Destination) error
}

// The introduce protocol's state.
type state interface {
	// Name of this state.
	Name() string
	// Whether this state allows transitioning into the next state.
	CanTransitionTo(next state) bool
	// Executes this state, returning a followup state to be immediately executed as well.
	// The 'noOp' state should be returned if the state has no followup.
	ExecuteInbound(ctx internalContext, msg *metaData) (followup state, err error)
	ExecuteOutbound(ctx internalContext, msg *metaData, dest *service.Destination) (followup state, err error)
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

func (s *noOp) ExecuteInbound(ctx internalContext, _ *metaData) (state, error) {
	return nil, errors.New("cannot execute no-op")
}

func (s *noOp) ExecuteOutbound(ctx internalContext, _ *metaData, _ *service.Destination) (state, error) {
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
	return next.Name() == stateNameArranging || next.Name() == stateNameDeciding
}

func (s *start) ExecuteInbound(ctx internalContext, _ *metaData) (state, error) {
	return &arranging{}, nil
}

func (s *start) ExecuteOutbound(ctx internalContext, _ *metaData, _ *service.Destination) (state, error) {
	return &noOp{}, nil
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

func (s *done) ExecuteInbound(ctx internalContext, _ *metaData) (state, error) {
	return &noOp{}, nil
}

func (s *done) ExecuteOutbound(ctx internalContext, _ *metaData, _ *service.Destination) (state, error) {
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

func (s *arranging) ExecuteInbound(ctx internalContext, m *metaData) (state, error) {
	// this code sends second proposal
	// first proposal was already sent by ExecuteOutbound
	destinations := m.dependency.Destinations()
	destination := destinations[len(destinations)-1]

	return &noOp{}, ctx.Send(&Proposal{
		Type:   ProposalMsgType,
		ID:     uuid.New().String(),
		Thread: &decorator.Thread{ID: m.ThreadID},
	}, "", destination)
}

func (s *arranging) ExecuteOutbound(ctx internalContext, m *metaData, dest *service.Destination) (state, error) {
	var proposal *Proposal
	if err := json.Unmarshal(m.Msg.Payload, &proposal); err != nil {
		return nil, fmt.Errorf("outbound unmarshal: %w", err)
	}
	// TODO: need to get a key
	return &noOp{}, ctx.Send(proposal, "", dest)
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

// destIDx returns destination index based on introducee index
func destIDx(idx int) int {
	if idx == 0 {
		return 1
	}

	return 0
}

func (s *delivering) ExecuteInbound(ctx internalContext, m *metaData) (state, error) {
	if isSkipProposal(m) {
		err := ctx.SendInvitation(m.dependency.Invitation(), m.dependency.Destinations()[0])
		if err != nil {
			return nil, fmt.Errorf("send inbound invitation (skip): %w", err)
		}

		return &done{}, nil
	}

	dests := m.dependency.Destinations()

	err := ctx.SendInvitation(m.Invitation, dests[destIDx(m.IntroduceeIndex)])
	if err != nil {
		return nil, fmt.Errorf("send inbound invitation: %w", err)
	}

	err = ctx.Send(&model.Ack{
		Type:   AckMsgType,
		ID:     uuid.New().String(),
		Thread: &decorator.Thread{ID: m.ThreadID},
	}, "", dests[m.IntroduceeIndex])

	if err != nil {
		return nil, fmt.Errorf("send ack: %w", err)
	}

	return &done{}, nil
}

func (s *delivering) ExecuteOutbound(ctx internalContext, _ *metaData, _ *service.Destination) (state, error) {
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

func (s *confirming) ExecuteInbound(ctx internalContext, _ *metaData) (state, error) {
	return nil, errors.New("confirming ExecuteInbound: not implemented yet")
}

func (s *confirming) ExecuteOutbound(ctx internalContext, _ *metaData, _ *service.Destination) (state, error) {
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

func (s *abandoning) ExecuteInbound(ctx internalContext, _ *metaData) (state, error) {
	return nil, errors.New("abandoning ExecuteInbound: not implemented yet")
}

func (s *abandoning) ExecuteOutbound(ctx internalContext, _ *metaData, _ *service.Destination) (state, error) {
	return nil, errors.New("abandoning ExecuteOutbound: not implemented yet")
}

// deciding state
type deciding struct {
}

func (s *deciding) Name() string {
	return stateNameDeciding
}

func (s *deciding) CanTransitionTo(next state) bool {
	return next.Name() == stateNameWaiting || next.Name() == stateNameDone
}

func (s *deciding) ExecuteInbound(ctx internalContext, m *metaData) (state, error) {
	return &waiting{}, ctx.Send(&Response{
		Type:       ResponseMsgType,
		ID:         uuid.New().String(),
		Thread:     &decorator.Thread{ID: m.ThreadID},
		Invitation: m.dependency.Invitation(),
	}, "", getInboundDestination())
}

func (s *deciding) ExecuteOutbound(ctx internalContext, _ *metaData, _ *service.Destination) (state, error) {
	return nil, errors.New("deciding ExecuteOutbound: not implemented yet")
}

// waiting state
type waiting struct {
}

func (s *waiting) Name() string {
	return stateNameWaiting
}

func (s *waiting) CanTransitionTo(next state) bool {
	return next.Name() == stateNameDone
}

func (s *waiting) ExecuteInbound(ctx internalContext, _ *metaData) (state, error) {
	return &noOp{}, nil
}

func (s *waiting) ExecuteOutbound(ctx internalContext, _ *metaData, _ *service.Destination) (state, error) {
	return nil, errors.New("waiting ExecuteOutbound: not implemented yet")
}
