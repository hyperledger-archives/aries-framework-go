/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/webnotifier"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

const (
	// InvalidRequestErrorCode is typically a code for validation errors
	// for invalid present proof controller requests.
	InvalidRequestErrorCode = command.Code(iota + command.PresentProof)
	// ActionsErrorCode is for failures in actions command.
	ActionsErrorCode
	// SendRequestPresentationErrorCode is for failures in send request presentation command.
	SendRequestPresentationErrorCode
	// AcceptRequestPresentationErrorCode is for failures in accept request presentation command.
	AcceptRequestPresentationErrorCode
	// AcceptProblemReportErrorCode is for failures in accept problem report command.
	AcceptProblemReportErrorCode
	// NegotiateRequestPresentationErrorCode is for failures in negotiate request presentation command.
	NegotiateRequestPresentationErrorCode
	// DeclineRequestPresentationErrorCode is for failures in decline request presentation command.
	DeclineRequestPresentationErrorCode
	// SendProposePresentationErrorCode is for failures in send propose presentation command.
	SendProposePresentationErrorCode
	// AcceptProposePresentationErrorCode is for failures in accept propose presentation command.
	AcceptProposePresentationErrorCode
	// DeclineProposePresentationErrorCode is for failures in decline propose presentation command.
	DeclineProposePresentationErrorCode
	// AcceptPresentationErrorCode is for failures in accept presentation command.
	AcceptPresentationErrorCode
	// DeclinePresentationErrorCode is for failures in decline presentation command.
	DeclinePresentationErrorCode
)

// constants for the PresentProof operations.
const (
	// command name.
	CommandName = "presentproof"

	Actions                        = "Actions"
	SendRequestPresentation        = "SendRequestPresentation"
	SendRequestPresentationV2      = "SendRequestPresentationV2"
	SendRequestPresentationV3      = "SendRequestPresentationV3"
	AcceptRequestPresentation      = "AcceptRequestPresentation"
	AcceptRequestPresentationV2    = "AcceptRequestPresentationV2"
	AcceptRequestPresentationV3    = "AcceptRequestPresentationV3"
	NegotiateRequestPresentation   = "NegotiateRequestPresentation"
	NegotiateRequestPresentationV2 = "NegotiateRequestPresentationV2"
	NegotiateRequestPresentationV3 = "NegotiateRequestPresentationV3"
	AcceptProblemReport            = "AcceptProblemReport"
	DeclineRequestPresentation     = "DeclineRequestPresentation"
	SendProposePresentation        = "SendProposePresentation"
	SendProposePresentationV2      = "SendProposePresentationV2"
	SendProposePresentationV3      = "SendProposePresentationV3"
	AcceptProposePresentation      = "AcceptProposePresentation"
	AcceptProposePresentationV2    = "AcceptProposePresentationV2"
	AcceptProposePresentationV3    = "AcceptProposePresentationV3"
	DeclineProposePresentation     = "DeclineProposePresentation"
	AcceptPresentation             = "AcceptPresentation"
	DeclinePresentation            = "DeclinePresentation"
)

const (
	// error messages.
	errEmptyPIID                = "empty PIID"
	errEmptyMyDID               = "empty MyDID"
	errEmptyTheirDID            = "empty TheirDID"
	errEmptyPresentation        = "empty Presentation"
	errEmptyProposePresentation = "empty ProposePresentation"
	errEmptyRequestPresentation = "empty RequestPresentation"
	errMissingConnection        = "no connection for given connection ID"

	// log constants.
	successString = "success"

	_actions = "_actions"
	_states  = "_states"
)

var logger = log.New("aries-framework/controller/presentproof")

// Command is controller command for present proof.
type Command struct {
	client *presentproof.Client
	lookup *connection.Lookup
}

// Provider contains dependencies for the protocol and is typically created by using aries.Context().
type Provider interface {
	Service(id string) (interface{}, error)
	ConnectionLookup() *connection.Lookup
}

// New returns new present proof controller command instance.
func New(ctx Provider, notifier command.Notifier) (*Command, error) {
	client, err := presentproof.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot create a client: %w", err)
	}

	// creates action channel
	actions := make(chan service.DIDCommAction)
	// registers action channel to listen for events
	if err := client.RegisterActionEvent(actions); err != nil {
		return nil, fmt.Errorf("register action event: %w", err)
	}

	// creates state channel
	states := make(chan service.StateMsg)
	// registers state channel to listen for events
	if err := client.RegisterMsgEvent(states); err != nil {
		return nil, fmt.Errorf("register msg event: %w", err)
	}

	obs := webnotifier.NewObserver(notifier)
	obs.RegisterAction(protocol.Name+_actions, actions)
	obs.RegisterStateMsg(protocol.Name+_states, states)

	return &Command{
		client: client,
		lookup: ctx.ConnectionLookup(),
	}, nil
}

// GetHandlers returns list of all commands supported by this controller command.
func (c *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, Actions, c.Actions),
		cmdutil.NewCommandHandler(CommandName, SendRequestPresentation, c.SendRequestPresentation),
		cmdutil.NewCommandHandler(CommandName, SendRequestPresentationV3, c.SendRequestPresentation),
		cmdutil.NewCommandHandler(CommandName, AcceptRequestPresentation, c.AcceptRequestPresentation),
		cmdutil.NewCommandHandler(CommandName, AcceptRequestPresentationV3, c.AcceptRequestPresentation),
		cmdutil.NewCommandHandler(CommandName, NegotiateRequestPresentation, c.NegotiateRequestPresentation),
		cmdutil.NewCommandHandler(CommandName, NegotiateRequestPresentationV3, c.NegotiateRequestPresentation),
		cmdutil.NewCommandHandler(CommandName, DeclineRequestPresentation, c.DeclineRequestPresentation),
		cmdutil.NewCommandHandler(CommandName, SendProposePresentation, c.SendProposePresentation),
		cmdutil.NewCommandHandler(CommandName, SendProposePresentationV3, c.SendProposePresentation),
		cmdutil.NewCommandHandler(CommandName, AcceptProposePresentation, c.AcceptProposePresentation),
		cmdutil.NewCommandHandler(CommandName, AcceptProposePresentationV3, c.AcceptProposePresentation),
		cmdutil.NewCommandHandler(CommandName, DeclineProposePresentation, c.DeclineProposePresentation),
		cmdutil.NewCommandHandler(CommandName, AcceptPresentation, c.AcceptPresentation),
		cmdutil.NewCommandHandler(CommandName, DeclinePresentation, c.DeclinePresentation),
		cmdutil.NewCommandHandler(CommandName, AcceptProblemReport, c.AcceptProblemReport),
	}
}

// Actions returns pending actions that have not yet to be executed or canceled.
func (c *Command) Actions(rw io.Writer, _ io.Reader) command.Error {
	result, err := c.client.Actions()
	if err != nil {
		logutil.LogError(logger, CommandName, Actions, err.Error())
		return command.NewExecuteError(ActionsErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ActionsResponse{
		Actions: result,
	}, logger)

	logutil.LogDebug(logger, CommandName, Actions, successString)

	return nil
}

// SendRequestPresentation is used by the Verifier to send a request presentation.
func (c *Command) SendRequestPresentation(rw io.Writer, req io.Reader) command.Error {
	var args SendRequestPresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, SendRequestPresentation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.MyDID == "" {
		logutil.LogDebug(logger, CommandName, SendRequestPresentation, errEmptyMyDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyMyDID))
	}

	if args.TheirDID == "" {
		logutil.LogDebug(logger, CommandName, SendRequestPresentation, errEmptyTheirDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyTheirDID))
	}

	if args.RequestPresentation == nil {
		logutil.LogDebug(logger, CommandName, SendRequestPresentation, errEmptyRequestPresentation)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyRequestPresentation))
	}

	rec, err := c.lookup.GetConnectionRecordByDIDs(args.MyDID, args.TheirDID)
	if err != nil {
		logutil.LogDebug(logger, CommandName, SendRequestPresentation, errMissingConnection)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errMissingConnection))
	}

	piid, err := c.client.SendRequestPresentation(args.RequestPresentation, rec)
	if err != nil {
		logutil.LogError(logger, CommandName, SendRequestPresentation, err.Error())
		return command.NewExecuteError(SendRequestPresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendRequestPresentationResponse{
		PIID: piid,
	}, logger)

	logutil.LogDebug(logger, CommandName, SendRequestPresentation, successString)

	return nil
}

// SendProposePresentation is used by the Prover to send a propose presentation.
func (c *Command) SendProposePresentation(rw io.Writer, req io.Reader) command.Error {
	var args SendProposePresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, SendProposePresentation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.MyDID == "" {
		logutil.LogDebug(logger, CommandName, SendProposePresentation, errEmptyMyDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyMyDID))
	}

	if args.TheirDID == "" {
		logutil.LogDebug(logger, CommandName, SendProposePresentation, errEmptyTheirDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyTheirDID))
	}

	if args.ProposePresentation == nil {
		logutil.LogDebug(logger, CommandName, SendProposePresentation, errEmptyProposePresentation)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyProposePresentation))
	}

	rec, err := c.lookup.GetConnectionRecordByDIDs(args.MyDID, args.TheirDID)
	if err != nil {
		logutil.LogDebug(logger, CommandName, SendProposePresentation, errMissingConnection)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errMissingConnection))
	}

	piid, err := c.client.SendProposePresentation(args.ProposePresentation, rec)
	if err != nil {
		logutil.LogError(logger, CommandName, SendProposePresentation, err.Error())
		return command.NewExecuteError(SendProposePresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendProposePresentationResponse{
		PIID: piid,
	}, logger)

	logutil.LogDebug(logger, CommandName, SendProposePresentation, successString)

	return nil
}

// AcceptRequestPresentation is used by the Prover is to accept a presentation request.
func (c *Command) AcceptRequestPresentation(rw io.Writer, req io.Reader) command.Error {
	var args AcceptRequestPresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, AcceptRequestPresentation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, AcceptRequestPresentation, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if args.Presentation == nil {
		logutil.LogDebug(logger, CommandName, AcceptRequestPresentation, errEmptyPresentation)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPresentation))
	}

	if err := c.client.AcceptRequestPresentation(args.PIID, args.Presentation, nil); err != nil {
		logutil.LogError(logger, CommandName, AcceptRequestPresentation, err.Error())
		return command.NewExecuteError(AcceptRequestPresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptRequestPresentationResponse{}, logger)

	logutil.LogDebug(logger, CommandName, AcceptRequestPresentation, successString)

	return nil
}

// NegotiateRequestPresentation is used by the Prover to counter a presentation request they received with a proposal.
func (c *Command) NegotiateRequestPresentation(rw io.Writer, req io.Reader) command.Error {
	var args NegotiateRequestPresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, NegotiateRequestPresentation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, NegotiateRequestPresentation, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if args.ProposePresentation == nil {
		logutil.LogDebug(logger, CommandName, NegotiateRequestPresentation, errEmptyProposePresentation)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyProposePresentation))
	}

	if err := c.client.NegotiateRequestPresentation(args.PIID, args.ProposePresentation); err != nil {
		logutil.LogError(logger, CommandName, NegotiateRequestPresentation, err.Error())
		return command.NewExecuteError(NegotiateRequestPresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &NegotiateRequestPresentationResponse{}, logger)

	logutil.LogDebug(logger, CommandName, NegotiateRequestPresentation, successString)

	return nil
}

// DeclineRequestPresentation is used when the Prover does not want to accept the request presentation.
func (c *Command) DeclineRequestPresentation(rw io.Writer, req io.Reader) command.Error {
	var args DeclineRequestPresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, DeclineRequestPresentation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, DeclineRequestPresentation, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.DeclineRequestPresentation(args.PIID, args.Reason); err != nil {
		logutil.LogError(logger, CommandName, DeclineRequestPresentation, err.Error())
		return command.NewExecuteError(DeclineRequestPresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeclineRequestPresentationResponse{}, logger)

	logutil.LogDebug(logger, CommandName, DeclineRequestPresentation, successString)

	return nil
}

// AcceptProposePresentation is used when the Verifier is willing to accept the propose presentation.
func (c *Command) AcceptProposePresentation(rw io.Writer, req io.Reader) command.Error {
	var args AcceptProposePresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, AcceptProposePresentation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, AcceptProposePresentation, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if args.RequestPresentation == nil {
		logutil.LogDebug(logger, CommandName, AcceptProposePresentation, errEmptyRequestPresentation)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyRequestPresentation))
	}

	if err := c.client.AcceptProposePresentation(args.PIID, args.RequestPresentation); err != nil {
		logutil.LogError(logger, CommandName, AcceptProposePresentation, err.Error())
		return command.NewExecuteError(AcceptProposePresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptProposePresentationResponse{}, logger)

	logutil.LogDebug(logger, CommandName, AcceptProposePresentation, successString)

	return nil
}

// DeclineProposePresentation is used when the Verifier does not want to accept the propose presentation.
func (c *Command) DeclineProposePresentation(rw io.Writer, req io.Reader) command.Error {
	var args DeclineProposePresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, DeclineProposePresentation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, DeclineProposePresentation, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.DeclineProposePresentation(args.PIID,
		presentproof.DeclineReason(args.Reason), presentproof.DeclineRedirect(args.RedirectURL)); err != nil {
		logutil.LogError(logger, CommandName, DeclineProposePresentation, err.Error())
		return command.NewExecuteError(DeclineProposePresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeclineProposePresentationResponse{}, logger)

	logutil.LogDebug(logger, CommandName, DeclineProposePresentation, successString)

	return nil
}

// AcceptPresentation is used by the Verifier to accept a presentation.
func (c *Command) AcceptPresentation(rw io.Writer, req io.Reader) command.Error {
	var args AcceptPresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, AcceptPresentation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, AcceptPresentation, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.AcceptPresentation(args.PIID, presentproof.AcceptByRequestingRedirect(args.RedirectURL),
		presentproof.AcceptByFriendlyNames(args.Names...)); err != nil {
		logutil.LogError(logger, CommandName, AcceptPresentation, err.Error())
		return command.NewExecuteError(AcceptPresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptPresentationResponse{}, logger)

	logutil.LogDebug(logger, CommandName, AcceptPresentation, successString)

	return nil
}

// AcceptProblemReport is used for accepting problem report.
func (c *Command) AcceptProblemReport(rw io.Writer, req io.Reader) command.Error {
	var args AcceptProblemReportArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, AcceptProblemReport, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, AcceptProblemReport, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.AcceptProblemReport(args.PIID); err != nil {
		logutil.LogError(logger, CommandName, AcceptProblemReport, err.Error())
		return command.NewExecuteError(AcceptProblemReportErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptProblemReportResponse{}, logger)

	logutil.LogDebug(logger, CommandName, AcceptProblemReport, successString)

	return nil
}

// DeclinePresentation is used by the Verifier to decline a presentation.
func (c *Command) DeclinePresentation(rw io.Writer, req io.Reader) command.Error {
	var args DeclinePresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, DeclinePresentation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, DeclinePresentation, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.DeclinePresentation(args.PIID,
		presentproof.DeclineReason(args.Reason), presentproof.DeclineRedirect(args.RedirectURL)); err != nil {
		logutil.LogError(logger, CommandName, DeclinePresentation, err.Error())
		return command.NewExecuteError(DeclinePresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeclinePresentationResponse{}, logger)

	logutil.LogDebug(logger, CommandName, DeclinePresentation, successString)

	return nil
}
