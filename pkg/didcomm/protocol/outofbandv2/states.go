/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofbandv2

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

const (
	// StateNameInitial is the initial state.
	StateNameInitial = "initial"
	// StateNameAwaitResponse is the state where a sender or a receiver are awaiting a response.
	StateNameAwaitResponse = "await-response"
	// StateNamePrepareResponse is the state where a receiver is preparing a response to the sender.
	StateNamePrepareResponse = "prepare-response"
	// StateNameDone is the final state.
	StateNameDone = "done"
)

type finisher func(service.Messenger) error

func noAction(service.Messenger) error {
	return nil
}

type dependencies struct {
	saveAttchStateFunc    func(*attachmentHandlingState) error
	dispatchAttachmntFunc func(string) error
}

// The outofband protocol's state.
type state interface {
	Name() string
	Execute(*context, *dependencies) (state, finisher, bool, error)
}

func stateFromName(n string) (state, error) {
	states := []state{
		&stateInitial{},
		&stateAwaitResponse{},
		&statePrepareResponse{},
		&stateDone{},
	}

	for i := range states {
		if states[i].Name() == n {
			return states[i], nil
		}
	}

	return nil, fmt.Errorf("unrecognized state name: %s", n)
}

func requiresApproval(msg service.DIDCommMsg) bool {
	return msg.Type() == InvitationMsgType
}

type stateInitial struct{}

func (s *stateInitial) Name() string {
	return StateNameInitial
}

func (s *stateInitial) Execute(ctx *context, _ *dependencies) (state, finisher, bool, error) {
	if ctx.Inbound { // inbound invitation
		return &statePrepareResponse{}, noAction, false, nil
	}

	// outbound invitation
	return &stateAwaitResponse{}, func(m service.Messenger) error {
		return m.Send(ctx.Msg, ctx.MyDID, ctx.TheirDID)
	}, true, nil
}

type stateAwaitResponse struct{}

func (s *stateAwaitResponse) Name() string {
	return StateNameAwaitResponse
}

func (s *stateAwaitResponse) Execute(ctx *context, deps *dependencies) (state, finisher, bool, error) {
	if !ctx.Inbound {
		return nil, nil, true, fmt.Errorf("cannot execute '%s' for outbound messages", s.Name())
	}

	return s.handleHandshakeReuseAccepted(ctx, deps)
}

func (s *stateAwaitResponse) handleHandshakeReuseAccepted(
	ctx *context, deps *dependencies) (state, finisher, bool, error) {
	logger.Debugf("handling %s with context: %+v", ctx.Msg.Type(), ctx)

	if len(ctx.Invitation.Requests) > 0 {
		go func() {
			logger.Debugf("dispatching invitation attachment...")

			err := deps.dispatchAttachmntFunc(ctx.Invitation.ID)
			if err != nil {
				logger.Errorf("failed to dispatch attachment: %s", err.Error())
			}
		}()
	}

	return &stateDone{}, noAction, false, nil
}

type statePrepareResponse struct{}

func (s *statePrepareResponse) Name() string {
	return StateNamePrepareResponse
}

func (s *statePrepareResponse) Execute(ctx *context, deps *dependencies) (state, finisher, bool, error) {
	logger.Debugf("handling %s with context: %+v", ctx.Msg.Type(), ctx)

	if ctx.Invitation != nil && len(ctx.Invitation.Requests) > 0 {
		callbackState := &attachmentHandlingState{
			ID:         ctx.Invitation.ID,
			Invitation: ctx.Invitation,
		}

		err := deps.saveAttchStateFunc(callbackState)
		if err != nil {
			return nil, nil, true, fmt.Errorf("failed to save attachment handling state: %w", err)
		}
	}

	return &stateDone{}, noAction, false, nil
}

type stateDone struct{}

func (s *stateDone) Name() string {
	return StateNameDone
}

func (s *stateDone) Execute(*context, *dependencies) (state, finisher, bool, error) {
	return &stateDone{}, noAction, true, nil
}
