/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
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

	connectionRecordCompletedState = "completed"
)

type finisher func(service.Messenger) error

func noAction(service.Messenger) error {
	return nil
}

type dependencies struct {
	connections           connectionRecorder
	didSvc                didExchSvc
	saveAttchStateFunc    func(*attachmentHandlingState) error
	dispatchAttachmntFunc func(string, string, string) error
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
	switch msg.Type() {
	case InvitationMsgType, HandshakeReuseMsgType:
		return true
	}

	return false
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

	// inbound HandshakeReuse or HandshakeReuseAccepted
	if ctx.Msg.Type() == HandshakeReuseMsgType {
		return s.handleHandshakeReuse(ctx, deps)
	}

	return s.handleHandshakeReuseAccepted(ctx, deps)
}

func (s *stateAwaitResponse) handleHandshakeReuse(ctx *context, deps *dependencies) (state, finisher, bool, error) {
	// incoming HandshakeReuse
	logger.Debugf("handling %s with context: %+v", ctx.Msg.Type(), ctx)

	connID, err := deps.connections.GetConnectionIDByDIDs(ctx.MyDID, ctx.TheirDID)
	if err != nil {
		return nil, nil, true, fmt.Errorf(
			"failed to fetch connection ID [myDID=%s theirDID=%s]: %w",
			ctx.MyDID, ctx.TheirDID, err,
		)
	}

	record, err := deps.connections.GetConnectionRecord(connID)
	if err != nil {
		return nil, nil, true, fmt.Errorf("failed to fetch connection record [connID=%s]: %w", connID, err)
	}

	if record.State != connectionRecordCompletedState {
		return nil, nil, true, fmt.Errorf(
			"unexpected state for connection with ID=%s: expected '%s' got '%s'",
			connID, connectionRecordCompletedState, record.State,
		)
	}

	return &stateDone{}, func(m service.Messenger) error {
		return m.ReplyToMsg(
			ctx.Msg,
			service.NewDIDCommMsgMap(&HandshakeReuseAccepted{
				ID:   uuid.New().String(),
				Type: HandshakeReuseAcceptedMsgType,
			}),
			ctx.MyDID,
			ctx.TheirDID,
		)
	}, false, nil
}

func (s *stateAwaitResponse) handleHandshakeReuseAccepted(
	ctx *context, deps *dependencies) (state, finisher, bool, error) {
	logger.Debugf("handling %s with context: %+v", ctx.Msg.Type(), ctx)

	if len(ctx.Invitation.Requests) > 0 {
		go func() {
			logger.Debugf("dispatching invitation attachment...")

			err := deps.dispatchAttachmntFunc(ctx.Invitation.ID, ctx.MyDID, ctx.TheirDID)
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

	// incoming Invitation
	if ctx.ReuseConnection != "" || ctx.ReuseAnyConnection {
		return s.connectionReuse(ctx, deps)
	}

	logger.Debugf("creating new connection using context: %+v", ctx)

	connID, err := deps.didSvc.RespondTo(ctx.DIDExchangeInv, ctx.RouterConnections)
	if err != nil {
		return nil, nil, true, fmt.Errorf("didexchange service failed to handle inbound invitation: %w", err)
	}

	ctx.ConnectionID = connID

	if len(ctx.Invitation.Requests) > 0 {
		callbackState := &attachmentHandlingState{
			ID:           ctx.Invitation.ID,
			ConnectionID: connID,
			Invitation:   ctx.Invitation,
		}

		err = deps.saveAttchStateFunc(callbackState)
		if err != nil {
			return nil, nil, true, fmt.Errorf("failed to save attachment handling state: %w", err)
		}
	}

	return &stateDone{}, noAction, false, nil
}

func (s *statePrepareResponse) connectionReuse(ctx *context, deps *dependencies) (state, finisher, bool, error) {
	logger.Debugf("reusing connection using context: %+v", ctx)

	// TODO query needs to be improved: https://github.com/hyperledger/aries-framework-go/issues/2732
	records, err := deps.connections.QueryConnectionRecords()
	if err != nil {
		return nil, nil, true, fmt.Errorf("connectionReuse: failed to fetch connection records: %w", err)
	}

	inv := ctx.Invitation

	var (
		record *connection.Record
		found  bool
	)

	if ctx.ReuseAnyConnection {
		for i := range inv.Services {
			if s, ok := inv.Services[i].(string); ok {
				record, found = findConnectionRecord(records, s)
				if found {
					break
				}
			}
		}
	} else {
		record, found = findConnectionRecord(records, ctx.ReuseConnection)
	}

	if !found {
		return nil, nil, true, errors.New("connectionReuse: no existing connection record found for the invitation")
	}

	ctx.ConnectionID = record.ConnectionID
	ctx.MyDID = record.MyDID
	ctx.TheirDID = record.TheirDID

	if len(ctx.Invitation.Requests) > 0 {
		callbackState := &attachmentHandlingState{
			ID:           ctx.Invitation.ID,
			ConnectionID: record.ConnectionID,
			Invitation:   ctx.Invitation,
		}

		err = deps.saveAttchStateFunc(callbackState)
		if err != nil {
			return nil, nil, true, fmt.Errorf("failed to save attachment handling state: %w", err)
		}
	}

	return &stateAwaitResponse{}, func(m service.Messenger) error {
		return m.ReplyToMsg(
			ctx.Msg,
			service.NewDIDCommMsgMap(&HandshakeReuse{
				ID:   uuid.New().String(),
				Type: HandshakeReuseMsgType,
			}),
			ctx.MyDID,
			ctx.TheirDID,
		)
	}, true, nil
}

type stateDone struct{}

func (s *stateDone) Name() string {
	return StateNameDone
}

func (s *stateDone) Execute(*context, *dependencies) (state, finisher, bool, error) {
	return &stateDone{}, noAction, true, nil
}

func findConnectionRecord(records []*connection.Record, theirDID string) (*connection.Record, bool) {
	for i := range records {
		record := records[i]

		if record.State != didexchange.StateIDCompleted {
			continue
		}

		// we may recognize their DID by either:
		//   - having received an invitation with their "public" DID (record.InvitationDID)
		//   - them providing a "ledger-less" DID during a prior DID-Exchange
		if record.InvitationDID == theirDID || record.TheirDID == theirDID {
			return record, true
		}
	}

	return nil, false
}
