/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package outofband

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/webnotifier"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
)

const (
	// InvalidRequestErrorCode is typically a code for validation errors
	// for invalid outofband controller requests.
	InvalidRequestErrorCode = command.Code(iota + command.Outofband)
	// CreateRequestErrorCode is for failures in create request command.
	CreateRequestErrorCode
	// CreateInvitationErrorCode is for failures in create invitation command.
	CreateInvitationErrorCode
	// AcceptRequestErrorCode is for failures in accept request command.
	AcceptRequestErrorCode
	// AcceptInvitationErrorCode is for failures in accept invitation command.
	AcceptInvitationErrorCode
	// ActionStopErrorCode is for failures in action stop command.
	ActionStopErrorCode
	// ActionsErrorCode is for failures in actions command.
	ActionsErrorCode
	// ActionContinueErrorCode is for failures in action continue command.
	ActionContinueErrorCode
)

// constants for out-of-band.
const (
	// command name.
	CommandName      = "outofband"
	CreateRequest    = "CreateRequest"
	CreateInvitation = "CreateInvitation"
	AcceptRequest    = "AcceptRequest"
	AcceptInvitation = "AcceptInvitation"
	ActionStop       = "ActionStop"
	Actions          = "Actions"
	ActionContinue   = "ActionContinue"

	// error messages.
	errOneAttachmentMustBeProvided = "at least one attachment must be provided"
	errEmptyRequest                = "request was not provided"
	errEmptyMyLabel                = "my_label was not provided"
	errEmptyPIID                   = "piid was not provided"
	// log constants.
	successString = "success"

	_actions = "_actions"
	_states  = "_states"
)

var logger = log.New("aries-framework/controller/outofband")

// Command is controller command for outofband.
type Command struct {
	client *outofband.Client
}

// New returns new outofband controller command instance.
func New(ctx outofband.Provider, notifier command.Notifier) (*Command, error) {
	client, err := outofband.New(ctx)
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

	return &Command{client: client}, nil
}

// GetHandlers returns list of all commands supported by this controller command.
func (c *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, CreateRequest, c.CreateRequest),
		cmdutil.NewCommandHandler(CommandName, CreateInvitation, c.CreateInvitation),
		cmdutil.NewCommandHandler(CommandName, AcceptRequest, c.AcceptRequest),
		cmdutil.NewCommandHandler(CommandName, AcceptInvitation, c.AcceptInvitation),
		cmdutil.NewCommandHandler(CommandName, Actions, c.Actions),
		cmdutil.NewCommandHandler(CommandName, ActionContinue, c.ActionContinue),
		cmdutil.NewCommandHandler(CommandName, ActionStop, c.ActionStop),
	}
}

// CreateRequest creates and saves an Out-Of-Band request message.
// At least one attachment must be provided.
// Service entries can be optionally provided. If none are provided then a new one will be automatically created for
// you.
func (c *Command) CreateRequest(rw io.Writer, req io.Reader) command.Error {
	var args CreateRequestArgs
	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, CreateRequest, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if len(args.Attachments) == 0 {
		logutil.LogDebug(logger, CommandName, CreateRequest, errOneAttachmentMustBeProvided)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errOneAttachmentMustBeProvided))
	}

	request, err := c.client.CreateRequest(args.Attachments, []outofband.MessageOption{
		outofband.WithGoal(args.Goal, args.GoalCode),
		outofband.WithLabel(args.Label),
		outofband.WithServices(args.Service...),
	}...)
	if err != nil {
		logutil.LogError(logger, CommandName, CreateRequest, err.Error())
		return command.NewExecuteError(CreateRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &CreateRequestResponse{
		Request: request,
	}, logger)

	logutil.LogDebug(logger, CommandName, CreateRequest, successString)

	return nil
}

// CreateInvitation creates and saves an out-of-band invitation.
// Protocols is an optional list of protocol identifier URIs that can be used to form connections. A default
// will be set if none are provided.
func (c *Command) CreateInvitation(rw io.Writer, req io.Reader) command.Error {
	var args CreateInvitationArgs
	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, CreateInvitation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	invitation, err := c.client.CreateInvitation(args.Protocols, []outofband.MessageOption{
		outofband.WithGoal(args.Goal, args.GoalCode),
		outofband.WithLabel(args.Label),
		outofband.WithServices(args.Service...),
	}...)
	if err != nil {
		logutil.LogError(logger, CommandName, CreateInvitation, err.Error())
		return command.NewExecuteError(CreateInvitationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &CreateInvitationResponse{
		Invitation: invitation,
	}, logger)

	logutil.LogDebug(logger, CommandName, CreateInvitation, successString)

	return nil
}

// AcceptRequest from another agent and return the ID of a new connection record.
func (c *Command) AcceptRequest(rw io.Writer, req io.Reader) command.Error {
	var args AcceptRequestArgs
	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, AcceptRequest, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.Request == nil {
		logutil.LogDebug(logger, CommandName, AcceptRequest, errEmptyRequest)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyRequest))
	}

	if args.MyLabel == "" {
		logutil.LogDebug(logger, CommandName, AcceptRequest, errEmptyMyLabel)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyMyLabel))
	}

	connID, err := c.client.AcceptRequest(args.Request, args.MyLabel)
	if err != nil {
		logutil.LogError(logger, CommandName, AcceptRequest, err.Error())
		return command.NewExecuteError(AcceptRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptRequestResponse{
		ConnectionID: connID,
	}, logger)

	logutil.LogDebug(logger, CommandName, AcceptRequest, successString)

	return nil
}

// AcceptInvitation from another agent and return the ID of the new connection records.
func (c *Command) AcceptInvitation(rw io.Writer, req io.Reader) command.Error {
	var args AcceptInvitationArgs
	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, AcceptInvitation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.Invitation == nil {
		logutil.LogDebug(logger, CommandName, AcceptInvitation, errEmptyRequest)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyRequest))
	}

	if args.MyLabel == "" {
		logutil.LogDebug(logger, CommandName, AcceptInvitation, errEmptyMyLabel)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyMyLabel))
	}

	connID, err := c.client.AcceptInvitation(args.Invitation, args.MyLabel)
	if err != nil {
		logutil.LogError(logger, CommandName, AcceptInvitation, err.Error())
		return command.NewExecuteError(AcceptInvitationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptInvitationResponse{
		ConnectionID: connID,
	}, logger)

	logutil.LogDebug(logger, CommandName, AcceptInvitation, successString)

	return nil
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

// ActionContinue allows continuing with the protocol after an action event was triggered.
func (c *Command) ActionContinue(rw io.Writer, req io.Reader) command.Error {
	var args ActionContinueArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, ActionContinue, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, ActionContinue, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.ActionContinue(args.PIID, args.Label); err != nil {
		logutil.LogError(logger, CommandName, ActionContinue, err.Error())
		return command.NewExecuteError(ActionContinueErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ActionContinueResponse{}, logger)

	logutil.LogDebug(logger, CommandName, ActionContinue, successString)

	return nil
}

// ActionStop stops the protocol after an action event was triggered.
func (c *Command) ActionStop(rw io.Writer, req io.Reader) command.Error {
	var args ActionStopArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, ActionStop, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, ActionStop, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.ActionStop(args.PIID, errors.New(args.Reason)); err != nil {
		logutil.LogError(logger, CommandName, ActionStop, err.Error())
		return command.NewExecuteError(ActionStopErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ActionStopResponse{}, logger)

	logutil.LogDebug(logger, CommandName, ActionStop, successString)

	return nil
}
