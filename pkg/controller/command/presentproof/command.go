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
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
)

const (
	// InvalidRequestErrorCode is typically a code for validation errors
	// for invalid present proof controller requests
	InvalidRequestErrorCode = command.Code(iota + command.PresentProof)
	// ActionsErrorCode is for failures in actions command
	ActionsErrorCode
	// SendRequestPresentationErrorCode is for failures in send request presentation command
	SendRequestPresentationErrorCode
	// AcceptRequestPresentationErrorCode is for failures in accept request presentation command
	AcceptRequestPresentationErrorCode
	// NegotiateRequestPresentationErrorCode is for failures in negotiate request presentation command
	NegotiateRequestPresentationErrorCode
	// DeclineRequestPresentationErrorCode is for failures in decline request presentation command
	DeclineRequestPresentationErrorCode
	// SendProposePresentationErrorCode is for failures in send propose presentation command
	SendProposePresentationErrorCode
	// AcceptProposePresentationErrorCode is for failures in accept propose presentation command
	AcceptProposePresentationErrorCode
	// DeclineProposePresentationErrorCode is for failures in decline propose presentation command
	DeclineProposePresentationErrorCode
	// AcceptPresentationErrorCode is for failures in accept presentation command
	AcceptPresentationErrorCode
	// DeclinePresentationErrorCode is for failures in decline presentation command
	DeclinePresentationErrorCode
)

const (
	// command name
	commandName = "presentproof"

	actions                      = "Actions"
	sendRequestPresentation      = "SendRequestPresentation"
	acceptRequestPresentation    = "AcceptRequestPresentation"
	negotiateRequestPresentation = "NegotiateRequestPresentation"
	declineRequestPresentation   = "DeclineRequestPresentation"
	sendProposePresentation      = "SendProposePresentation"
	acceptProposePresentation    = "AcceptProposePresentation"
	declineProposePresentation   = "DeclineProposePresentation"
	acceptPresentation           = "AcceptPresentation"
	declinePresentation          = "DeclinePresentation"
)

const (
	// error messages
	errEmptyPIID                = "empty PIID"
	errEmptyMyDID               = "empty MyDID"
	errEmptyTheirDID            = "empty TheirDID"
	errEmptyPresentation        = "empty Presentation"
	errEmptyProposePresentation = "empty ProposePresentation"
	errEmptyRequestPresentation = "empty RequestPresentation"

	// log constants
	successString = "success"
)

var logger = log.New("aries-framework/controller/presentproof")

// Command is controller command for present proof
type Command struct {
	client *presentproof.Client
}

// New returns new present proof controller command instance
func New(ctx presentproof.Provider) (*Command, error) {
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

	// this code listens for the action events and does nothing
	// this trick is used to avoid error such as `no clients are registered to handle the message`
	go func() {
		for range actions {
		}
	}()

	return &Command{client: client}, nil
}

// GetHandlers returns list of all commands supported by this controller command
func (c *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(commandName, actions, c.Actions),
		cmdutil.NewCommandHandler(commandName, sendRequestPresentation, c.SendRequestPresentation),
		cmdutil.NewCommandHandler(commandName, acceptRequestPresentation, c.AcceptRequestPresentation),
		cmdutil.NewCommandHandler(commandName, negotiateRequestPresentation, c.NegotiateRequestPresentation),
		cmdutil.NewCommandHandler(commandName, declineRequestPresentation, c.DeclineRequestPresentation),
		cmdutil.NewCommandHandler(commandName, sendProposePresentation, c.SendProposePresentation),
		cmdutil.NewCommandHandler(commandName, acceptProposePresentation, c.AcceptProposePresentation),
		cmdutil.NewCommandHandler(commandName, declineProposePresentation, c.DeclineProposePresentation),
		cmdutil.NewCommandHandler(commandName, acceptPresentation, c.AcceptPresentation),
		cmdutil.NewCommandHandler(commandName, declinePresentation, c.DeclinePresentation),
	}
}

// Actions returns pending actions that have not yet to be executed or canceled.
func (c *Command) Actions(rw io.Writer, _ io.Reader) command.Error {
	result, err := c.client.Actions()
	if err != nil {
		logutil.LogError(logger, commandName, actions, err.Error())
		return command.NewExecuteError(ActionsErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ActionsResponse{
		Actions: result,
	}, logger)

	logutil.LogDebug(logger, commandName, actions, successString)

	return nil
}

// SendRequestPresentation is used by the Verifier to send a request presentation.
// nolint: dupl
func (c *Command) SendRequestPresentation(rw io.Writer, req io.Reader) command.Error {
	var args SendRequestPresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, sendRequestPresentation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.MyDID == "" {
		logutil.LogDebug(logger, commandName, sendRequestPresentation, errEmptyMyDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyMyDID))
	}

	if args.TheirDID == "" {
		logutil.LogDebug(logger, commandName, sendRequestPresentation, errEmptyTheirDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyTheirDID))
	}

	if args.RequestPresentation == nil {
		logutil.LogDebug(logger, commandName, sendRequestPresentation, errEmptyRequestPresentation)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyRequestPresentation))
	}

	if err := c.client.SendRequestPresentation(args.RequestPresentation, args.MyDID, args.TheirDID); err != nil {
		logutil.LogError(logger, commandName, sendRequestPresentation, err.Error())
		return command.NewExecuteError(SendRequestPresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendRequestPresentationResponse{}, logger)

	logutil.LogDebug(logger, commandName, sendRequestPresentation, successString)

	return nil
}

// SendProposePresentation is used by the Prover to send a propose presentation.
// nolint: dupl
func (c *Command) SendProposePresentation(rw io.Writer, req io.Reader) command.Error {
	var args SendProposePresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, sendProposePresentation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.MyDID == "" {
		logutil.LogDebug(logger, commandName, sendProposePresentation, errEmptyMyDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyMyDID))
	}

	if args.TheirDID == "" {
		logutil.LogDebug(logger, commandName, sendProposePresentation, errEmptyTheirDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyTheirDID))
	}

	if args.ProposePresentation == nil {
		logutil.LogDebug(logger, commandName, sendProposePresentation, errEmptyProposePresentation)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyProposePresentation))
	}

	if err := c.client.SendProposePresentation(args.ProposePresentation, args.MyDID, args.TheirDID); err != nil {
		logutil.LogError(logger, commandName, sendProposePresentation, err.Error())
		return command.NewExecuteError(SendProposePresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendProposePresentationResponse{}, logger)

	logutil.LogDebug(logger, commandName, sendProposePresentation, successString)

	return nil
}

// AcceptRequestPresentation is used by the Prover is to accept a presentation request.
// nolint: dupl
func (c *Command) AcceptRequestPresentation(rw io.Writer, req io.Reader) command.Error {
	var args AcceptRequestPresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, acceptRequestPresentation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, commandName, acceptRequestPresentation, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if args.Presentation == nil {
		logutil.LogDebug(logger, commandName, acceptRequestPresentation, errEmptyPresentation)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPresentation))
	}

	if err := c.client.AcceptRequestPresentation(args.PIID, args.Presentation); err != nil {
		logutil.LogError(logger, commandName, acceptRequestPresentation, err.Error())
		return command.NewExecuteError(AcceptRequestPresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptRequestPresentationResponse{}, logger)

	logutil.LogDebug(logger, commandName, acceptRequestPresentation, successString)

	return nil
}

// NegotiateRequestPresentation is used by the Prover to counter a presentation request they received with a proposal.
// nolint: dupl
func (c *Command) NegotiateRequestPresentation(rw io.Writer, req io.Reader) command.Error {
	var args NegotiateRequestPresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, negotiateRequestPresentation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, commandName, negotiateRequestPresentation, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if args.ProposePresentation == nil {
		logutil.LogDebug(logger, commandName, negotiateRequestPresentation, errEmptyProposePresentation)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyProposePresentation))
	}

	if err := c.client.NegotiateRequestPresentation(args.PIID, args.ProposePresentation); err != nil {
		logutil.LogError(logger, commandName, negotiateRequestPresentation, err.Error())
		return command.NewExecuteError(NegotiateRequestPresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &NegotiateRequestPresentationResponse{}, logger)

	logutil.LogDebug(logger, commandName, negotiateRequestPresentation, successString)

	return nil
}

// DeclineRequestPresentation is used when the Prover does not want to accept the request presentation.
// nolint: dupl
func (c *Command) DeclineRequestPresentation(rw io.Writer, req io.Reader) command.Error {
	var args DeclineRequestPresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, declineRequestPresentation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, commandName, declineRequestPresentation, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.DeclineRequestPresentation(args.PIID, args.Reason); err != nil {
		logutil.LogError(logger, commandName, declineRequestPresentation, err.Error())
		return command.NewExecuteError(DeclineRequestPresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeclineRequestPresentationResponse{}, logger)

	logutil.LogDebug(logger, commandName, declineRequestPresentation, successString)

	return nil
}

// AcceptProposePresentation is used when the Verifier is willing to accept the propose presentation.
// nolint: dupl
func (c *Command) AcceptProposePresentation(rw io.Writer, req io.Reader) command.Error {
	var args AcceptProposePresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, acceptProposePresentation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, commandName, acceptProposePresentation, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if args.RequestPresentation == nil {
		logutil.LogDebug(logger, commandName, acceptProposePresentation, errEmptyRequestPresentation)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyRequestPresentation))
	}

	if err := c.client.AcceptProposePresentation(args.PIID, args.RequestPresentation); err != nil {
		logutil.LogError(logger, commandName, acceptProposePresentation, err.Error())
		return command.NewExecuteError(AcceptProposePresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptProposePresentationResponse{}, logger)

	logutil.LogDebug(logger, commandName, acceptProposePresentation, successString)

	return nil
}

// DeclineProposePresentation is used when the Verifier does not want to accept the propose presentation.
// nolint: dupl
func (c *Command) DeclineProposePresentation(rw io.Writer, req io.Reader) command.Error {
	var args DeclineProposePresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, declineProposePresentation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, commandName, declineProposePresentation, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.DeclineProposePresentation(args.PIID, args.Reason); err != nil {
		logutil.LogError(logger, commandName, declineProposePresentation, err.Error())
		return command.NewExecuteError(DeclineProposePresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeclineProposePresentationResponse{}, logger)

	logutil.LogDebug(logger, commandName, declineProposePresentation, successString)

	return nil
}

// AcceptPresentation is used by the Verifier to accept a presentation.
// nolint: dupl
func (c *Command) AcceptPresentation(rw io.Writer, req io.Reader) command.Error {
	var args AcceptPresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, acceptPresentation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, commandName, acceptPresentation, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.AcceptPresentation(args.PIID, args.Names...); err != nil {
		logutil.LogError(logger, commandName, acceptPresentation, err.Error())
		return command.NewExecuteError(AcceptPresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptPresentationResponse{}, logger)

	logutil.LogDebug(logger, commandName, acceptPresentation, successString)

	return nil
}

// DeclinePresentation is used by the Verifier to decline a presentation.
// nolint: dupl
func (c *Command) DeclinePresentation(rw io.Writer, req io.Reader) command.Error {
	var args DeclinePresentationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, declinePresentation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, commandName, declinePresentation, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.DeclinePresentation(args.PIID, args.Reason); err != nil {
		logutil.LogError(logger, commandName, declinePresentation, err.Error())
		return command.NewExecuteError(DeclinePresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeclinePresentationResponse{}, logger)

	logutil.LogDebug(logger, commandName, declinePresentation, successString)

	return nil
}
