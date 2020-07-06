/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/client/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/webnotifier"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
)

var logger = log.New("aries-framework/controller/introduce")

const (
	// InvalidRequestErrorCode is typically a code for validation errors
	// for invalid introduce controller requests
	InvalidRequestErrorCode = command.Code(iota + command.Introduce)
	// SendProposalErrorCode is for failures in send proposal command
	SendProposalErrorCode
	// SendProposalWithOOBRequestErrorCode is for failures in send proposal with OOBRequest command
	SendProposalWithOOBRequestErrorCode
	// SendRequestErrorCode is for failures in send request command
	SendRequestErrorCode
	// AcceptProposalWithOOBRequestErrorCode is for failures in accept proposal with OOBRequest command
	AcceptProposalWithOOBRequestErrorCode
	// AcceptProposalErrorCode is for failures in accept proposal command
	AcceptProposalErrorCode
	// AcceptRequestWithPublicOOBRequestErrorCode is for failures in accept request with public OOBRequest command
	AcceptRequestWithPublicOOBRequestErrorCode
	// AcceptRequestWithRecipientsErrorCode is for failures in accept request with recipients command
	AcceptRequestWithRecipientsErrorCode
	// DeclineProposalErrorCode failures in decline proposal command
	DeclineProposalErrorCode
	// DeclineRequestErrorCode failures in decline request command
	DeclineRequestErrorCode
	// ActionsErrorCode failures in actions command
	ActionsErrorCode
)

const (
	maxRecipients = 2
	// command name
	commandName = "introduce"

	actions                           = "Actions"
	sendProposal                      = "SendProposal"
	sendProposalWithOOBRequest        = "SendProposalWithOOBRequest"
	sendRequest                       = "SendRequest"
	acceptProposalWithOOBRequest      = "AcceptProposalWithOOBRequest"
	acceptProposal                    = "AcceptProposal"
	acceptRequestWithPublicOOBRequest = "AcceptRequestWithPublicOOBRequest"
	acceptRequestWithRecipients       = "AcceptRequestWithRecipients"
	declineProposal                   = "DeclineProposal"
	declineRequest                    = "DeclineRequest"
	// error messages
	errTwoRecipients          = "two recipients must be specified"
	errEmptyRequest           = "empty request"
	errEmptyRecipient         = "empty recipient"
	errEmptyMyDID             = "empty my_did"
	errEmptyTheirDID          = "empty their_did"
	errEmptyPleaseIntroduceTo = "empty please_introduce_to"
	errEmptyPIID              = "empty piid"
	errEmptyTo                = "empty to"
	// log constants
	successString = "success"

	_actions = "_actions"
	_states  = "_states"
)

// Command is controller command for introduce
type Command struct {
	client *introduce.Client
}

// New returns new introduce controller command instance
func New(ctx introduce.Provider, notifier command.Notifier) (*Command, error) {
	client, err := introduce.New(ctx)
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
	obs.RegisterAction(protocol.Introduce+_actions, actions)
	obs.RegisterStateMsg(protocol.Introduce+_states, states)

	return &Command{client: client}, nil
}

// GetHandlers returns list of all commands supported by this controller command
func (c *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(commandName, actions, c.Actions),
		cmdutil.NewCommandHandler(commandName, sendProposal, c.SendProposal),
		cmdutil.NewCommandHandler(commandName, sendProposalWithOOBRequest, c.SendProposalWithOOBRequest),
		cmdutil.NewCommandHandler(commandName, sendRequest, c.SendRequest),
		cmdutil.NewCommandHandler(commandName, acceptProposalWithOOBRequest, c.AcceptProposalWithOOBRequest),
		cmdutil.NewCommandHandler(commandName, acceptProposal, c.AcceptProposal),
		cmdutil.NewCommandHandler(commandName, acceptRequestWithPublicOOBRequest, c.AcceptRequestWithPublicOOBRequest),
		cmdutil.NewCommandHandler(commandName, acceptRequestWithRecipients, c.AcceptRequestWithRecipients),
		cmdutil.NewCommandHandler(commandName, declineProposal, c.DeclineProposal),
		cmdutil.NewCommandHandler(commandName, declineRequest, c.DeclineRequest),
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

// SendProposal sends a proposal to the introducees (the client has not published an out-of-band message).
func (c *Command) SendProposal(rw io.Writer, req io.Reader) command.Error {
	var args SendProposalArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, sendProposal, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if len(args.Recipients) != maxRecipients {
		logutil.LogDebug(logger, commandName, sendProposal, errTwoRecipients)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errTwoRecipients))
	}

	piid, err := c.client.SendProposal(args.Recipients[0], args.Recipients[1])
	if err != nil {
		logutil.LogError(logger, commandName, sendProposal, err.Error())
		return command.NewExecuteError(SendProposalErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendProposalResponse{PIID: piid}, logger)

	logutil.LogDebug(logger, commandName, sendProposal, successString)

	return nil
}

// SendProposalWithOOBRequest sends a proposal to the introducee (the client has published an out-of-band request).
func (c *Command) SendProposalWithOOBRequest(rw io.Writer, req io.Reader) command.Error {
	var args SendProposalWithOOBRequestArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, sendProposalWithOOBRequest, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.Request == nil {
		logutil.LogDebug(logger, commandName, sendProposalWithOOBRequest, errEmptyRequest)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyRequest))
	}

	if args.Recipient == nil {
		logutil.LogDebug(logger, commandName, sendProposalWithOOBRequest, errEmptyRecipient)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyRecipient))
	}

	piid, err := c.client.SendProposalWithOOBRequest(args.Request, args.Recipient)
	if err != nil {
		logutil.LogError(logger, commandName, sendProposalWithOOBRequest, err.Error())
		return command.NewExecuteError(SendProposalWithOOBRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendProposalWithOOBRequestResponse{PIID: piid}, logger)

	logutil.LogDebug(logger, commandName, sendProposalWithOOBRequest, successString)

	return nil
}

// SendRequest sends a request.
// Sending a request means that the introducee is willing to share their own out-of-band message.
func (c *Command) SendRequest(rw io.Writer, req io.Reader) command.Error {
	var args SendRequestArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, sendRequest, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.MyDID == "" {
		logutil.LogDebug(logger, commandName, sendRequest, errEmptyMyDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyMyDID))
	}

	if args.TheirDID == "" {
		logutil.LogDebug(logger, commandName, sendRequest, errEmptyTheirDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyTheirDID))
	}

	if args.PleaseIntroduceTo == nil {
		logutil.LogDebug(logger, commandName, sendRequest, errEmptyPleaseIntroduceTo)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPleaseIntroduceTo))
	}

	piid, err := c.client.SendRequest(args.PleaseIntroduceTo, args.MyDID, args.TheirDID)
	if err != nil {
		logutil.LogError(logger, commandName, sendRequest, err.Error())
		return command.NewExecuteError(SendRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendRequestResponse{PIID: piid}, logger)

	logutil.LogDebug(logger, commandName, sendRequest, successString)

	return nil
}

// AcceptProposalWithOOBRequest is used when introducee wants to provide an out-of-band request.
func (c *Command) AcceptProposalWithOOBRequest(rw io.Writer, req io.Reader) command.Error {
	var args AcceptProposalWithOOBRequestArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, acceptProposalWithOOBRequest, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, commandName, acceptProposalWithOOBRequest, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if args.Request == nil {
		logutil.LogDebug(logger, commandName, acceptProposalWithOOBRequest, errEmptyRequest)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyRequest))
	}

	if err := c.client.AcceptProposalWithOOBRequest(args.PIID, args.Request); err != nil {
		logutil.LogError(logger, commandName, acceptProposalWithOOBRequest, err.Error())
		return command.NewExecuteError(AcceptProposalWithOOBRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptProposalWithOOBRequestResponse{}, logger)

	logutil.LogDebug(logger, commandName, acceptProposalWithOOBRequest, successString)

	return nil
}

// AcceptProposal is used when introducee wants to accept a proposal without providing a OOBRequest.
func (c *Command) AcceptProposal(rw io.Writer, req io.Reader) command.Error {
	var args AcceptProposalArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, acceptProposal, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, commandName, acceptProposal, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.AcceptProposal(args.PIID); err != nil {
		logutil.LogError(logger, commandName, acceptProposal, err.Error())
		return command.NewExecuteError(AcceptProposalErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptProposalResponse{}, logger)

	logutil.LogDebug(logger, commandName, acceptProposal, successString)

	return nil
}

// AcceptRequestWithPublicOOBRequest is used when introducer wants to provide a published out-of-band request.
// nolint: dupl
func (c *Command) AcceptRequestWithPublicOOBRequest(rw io.Writer, req io.Reader) command.Error {
	var args AcceptRequestWithPublicOOBRequestArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, acceptRequestWithPublicOOBRequest, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, commandName, acceptRequestWithPublicOOBRequest, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if args.Request == nil {
		logutil.LogDebug(logger, commandName, acceptRequestWithPublicOOBRequest, errEmptyRequest)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyRequest))
	}

	if args.To == nil {
		logutil.LogDebug(logger, commandName, acceptRequestWithPublicOOBRequest, errEmptyTo)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyTo))
	}

	if err := c.client.AcceptRequestWithPublicOOBRequest(args.PIID, args.Request, args.To); err != nil {
		logutil.LogError(logger, commandName, acceptRequestWithPublicOOBRequest, err.Error())
		return command.NewExecuteError(AcceptRequestWithPublicOOBRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptRequestWithPublicOOBRequestResponse{}, logger)

	logutil.LogDebug(logger, commandName, acceptRequestWithPublicOOBRequest, successString)

	return nil
}

// AcceptRequestWithRecipients is used when the introducer does not have a published out-of-band message on hand
// but he is willing to introduce agents to each other.
// nolint: dupl
func (c *Command) AcceptRequestWithRecipients(rw io.Writer, req io.Reader) command.Error {
	var args AcceptRequestWithRecipientsArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, acceptRequestWithRecipients, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, commandName, acceptRequestWithRecipients, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if args.Recipient == nil {
		logutil.LogDebug(logger, commandName, acceptRequestWithRecipients, errEmptyRecipient)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyRecipient))
	}

	if args.To == nil {
		logutil.LogDebug(logger, commandName, acceptRequestWithRecipients, errEmptyTo)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyTo))
	}

	if err := c.client.AcceptRequestWithRecipients(args.PIID, args.To, args.Recipient); err != nil {
		logutil.LogError(logger, commandName, acceptRequestWithRecipients, err.Error())
		return command.NewExecuteError(AcceptRequestWithRecipientsErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptRequestWithRecipientsResponse{}, logger)

	logutil.LogDebug(logger, commandName, acceptRequestWithRecipients, successString)

	return nil
}

// DeclineProposal is used to reject the proposal.
// nolint: dupl
func (c *Command) DeclineProposal(rw io.Writer, req io.Reader) command.Error {
	var args DeclineProposalArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, declineProposal, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, commandName, declineProposal, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.DeclineProposal(args.PIID, args.Reason); err != nil {
		logutil.LogError(logger, commandName, declineProposal, err.Error())
		return command.NewExecuteError(DeclineProposalErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeclineProposalResponse{}, logger)

	logutil.LogDebug(logger, commandName, declineProposal, successString)

	return nil
}

// DeclineRequest is used to reject the request.
// nolint: dupl
func (c *Command) DeclineRequest(rw io.Writer, req io.Reader) command.Error {
	var args DeclineRequestArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, declineRequest, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, commandName, declineRequest, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.DeclineRequest(args.PIID, args.Reason); err != nil {
		logutil.LogError(logger, commandName, declineRequest, err.Error())
		return command.NewExecuteError(DeclineRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeclineRequestResponse{}, logger)

	logutil.LogDebug(logger, commandName, declineRequest, successString)

	return nil
}
