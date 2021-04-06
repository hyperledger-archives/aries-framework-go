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
	// for invalid introduce controller requests.
	InvalidRequestErrorCode = command.Code(iota + command.Introduce)
	// SendProposalErrorCode is for failures in send proposal command.
	SendProposalErrorCode
	// SendProposalWithOOBRequestErrorCode is for failures in send proposal with OOBRequest command.
	SendProposalWithOOBRequestErrorCode
	// SendRequestErrorCode is for failures in send request command.
	SendRequestErrorCode
	// AcceptProposalWithOOBRequestErrorCode is for failures in accept proposal with OOBRequest command.
	AcceptProposalWithOOBRequestErrorCode
	// AcceptProposalErrorCode is for failures in accept proposal command.
	AcceptProposalErrorCode
	// AcceptRequestWithPublicOOBInvitationErrorCode is for failures in accept request with public OOBRequest command.
	AcceptRequestWithPublicOOBInvitationErrorCode
	// AcceptRequestWithRecipientsErrorCode is for failures in accept request with recipients command.
	AcceptRequestWithRecipientsErrorCode
	// DeclineProposalErrorCode failures in decline proposal command.
	DeclineProposalErrorCode
	// DeclineRequestErrorCode failures in decline request command.
	DeclineRequestErrorCode
	// ActionsErrorCode failures in actions command.
	ActionsErrorCode
	// AcceptProblemReportErrorCode is for failures in accept problem report command.
	AcceptProblemReportErrorCode
)

// constants for command introduce.
const (
	maxRecipients = 2

	CommandName = "introduce"

	Actions                              = "Actions"
	SendProposal                         = "SendProposal"
	SendProposalWithOOBInvitation        = "SendProposalWithOOBInvitation"
	SendRequest                          = "SendRequest"
	AcceptProposalWithOOBInvitation      = "AcceptProposalWithOOBInvitation"
	AcceptProposal                       = "AcceptProposal"
	AcceptRequestWithPublicOOBInvitation = "AcceptRequestWithPublicOOBInvitation"
	AcceptRequestWithRecipients          = "AcceptRequestWithRecipients"
	DeclineProposal                      = "DeclineProposal"
	DeclineRequest                       = "DeclineRequest"
	AcceptProblemReport                  = "AcceptProblemReport"
	// error messages.
	errTwoRecipients          = "two recipients must be specified"
	errEmptyInvitation        = "empty invitation"
	errEmptyRecipient         = "empty recipient"
	errEmptyMyDID             = "empty my_did"
	errEmptyTheirDID          = "empty their_did"
	errEmptyPleaseIntroduceTo = "empty please_introduce_to"
	errEmptyPIID              = "empty piid"
	errEmptyTo                = "empty to"
	// log constants.
	successString = "success"

	_actions = "_actions"
	_states  = "_states"
)

// Command is controller command for introduce.
type Command struct {
	client *introduce.Client
}

// New returns new introduce controller command instance.
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

// GetHandlers returns list of all commands supported by this controller command.
func (c *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, Actions, c.Actions),
		cmdutil.NewCommandHandler(CommandName, SendProposal, c.SendProposal),
		cmdutil.NewCommandHandler(CommandName, SendProposalWithOOBInvitation, c.SendProposalWithOOBInvitation),
		cmdutil.NewCommandHandler(CommandName, SendRequest, c.SendRequest),
		cmdutil.NewCommandHandler(CommandName, AcceptProposalWithOOBInvitation, c.AcceptProposalWithOOBInvitation),
		cmdutil.NewCommandHandler(CommandName, AcceptProposal, c.AcceptProposal),
		cmdutil.NewCommandHandler(CommandName, AcceptRequestWithPublicOOBInvitation, c.AcceptRequestWithPublicOOBInvitation),
		cmdutil.NewCommandHandler(CommandName, AcceptRequestWithRecipients, c.AcceptRequestWithRecipients),
		cmdutil.NewCommandHandler(CommandName, DeclineProposal, c.DeclineProposal),
		cmdutil.NewCommandHandler(CommandName, DeclineRequest, c.DeclineRequest),
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

// SendProposal sends a proposal to the introducees (the client has not published an out-of-band message).
func (c *Command) SendProposal(rw io.Writer, req io.Reader) command.Error {
	var args SendProposalArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, SendProposal, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if len(args.Recipients) != maxRecipients {
		logutil.LogDebug(logger, CommandName, SendProposal, errTwoRecipients)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errTwoRecipients))
	}

	piid, err := c.client.SendProposal(args.Recipients[0], args.Recipients[1])
	if err != nil {
		logutil.LogError(logger, CommandName, SendProposal, err.Error())
		return command.NewExecuteError(SendProposalErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendProposalResponse{PIID: piid}, logger)

	logutil.LogDebug(logger, CommandName, SendProposal, successString)

	return nil
}

// SendProposalWithOOBInvitation sends a proposal to the introducee (the client has published an out-of-band
// invitation).
func (c *Command) SendProposalWithOOBInvitation(rw io.Writer, req io.Reader) command.Error {
	var args SendProposalWithOOBInvitationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, SendProposalWithOOBInvitation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.Invitation == nil {
		logutil.LogDebug(logger, CommandName, SendProposalWithOOBInvitation, errEmptyInvitation)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyInvitation))
	}

	if args.Recipient == nil {
		logutil.LogDebug(logger, CommandName, SendProposalWithOOBInvitation, errEmptyRecipient)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyRecipient))
	}

	piid, err := c.client.SendProposalWithOOBInvitation(args.Invitation, args.Recipient)
	if err != nil {
		logutil.LogError(logger, CommandName, SendProposalWithOOBInvitation, err.Error())
		return command.NewExecuteError(SendProposalWithOOBRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendProposalWithOOBRequestResponse{PIID: piid}, logger)

	logutil.LogDebug(logger, CommandName, SendProposalWithOOBInvitation, successString)

	return nil
}

// SendRequest sends a request.
// Sending a request means that the introducee is willing to share their own out-of-band message.
func (c *Command) SendRequest(rw io.Writer, req io.Reader) command.Error {
	var args SendRequestArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, SendRequest, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.MyDID == "" {
		logutil.LogDebug(logger, CommandName, SendRequest, errEmptyMyDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyMyDID))
	}

	if args.TheirDID == "" {
		logutil.LogDebug(logger, CommandName, SendRequest, errEmptyTheirDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyTheirDID))
	}

	if args.PleaseIntroduceTo == nil {
		logutil.LogDebug(logger, CommandName, SendRequest, errEmptyPleaseIntroduceTo)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPleaseIntroduceTo))
	}

	piid, err := c.client.SendRequest(args.PleaseIntroduceTo, args.MyDID, args.TheirDID)
	if err != nil {
		logutil.LogError(logger, CommandName, SendRequest, err.Error())
		return command.NewExecuteError(SendRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendRequestResponse{PIID: piid}, logger)

	logutil.LogDebug(logger, CommandName, SendRequest, successString)

	return nil
}

// AcceptProposalWithOOBInvitation is used when introducee wants to provide an out-of-band request.
func (c *Command) AcceptProposalWithOOBInvitation(rw io.Writer, req io.Reader) command.Error {
	var args AcceptProposalWithOOBInvitationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, AcceptProposalWithOOBInvitation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, AcceptProposalWithOOBInvitation, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if args.Invitation == nil {
		logutil.LogDebug(logger, CommandName, AcceptProposalWithOOBInvitation, errEmptyInvitation)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyInvitation))
	}

	if err := c.client.AcceptProposalWithOOBInvitation(args.PIID, args.Invitation); err != nil {
		logutil.LogError(logger, CommandName, AcceptProposalWithOOBInvitation, err.Error())
		return command.NewExecuteError(AcceptProposalWithOOBRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptProposalWithOOBInvitationResponse{}, logger)

	logutil.LogDebug(logger, CommandName, AcceptProposalWithOOBInvitation, successString)

	return nil
}

// AcceptProposal is used when introducee wants to accept a proposal without providing a OOBRequest.
func (c *Command) AcceptProposal(rw io.Writer, req io.Reader) command.Error {
	var args AcceptProposalArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, AcceptProposal, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, AcceptProposal, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.AcceptProposal(args.PIID); err != nil {
		logutil.LogError(logger, CommandName, AcceptProposal, err.Error())
		return command.NewExecuteError(AcceptProposalErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptProposalResponse{}, logger)

	logutil.LogDebug(logger, CommandName, AcceptProposal, successString)

	return nil
}

// AcceptRequestWithPublicOOBInvitation is used when introducer wants to provide a published out-of-band request.
func (c *Command) AcceptRequestWithPublicOOBInvitation(rw io.Writer, req io.Reader) command.Error {
	var args AcceptRequestWithPublicOOBInvitationArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, AcceptRequestWithPublicOOBInvitation, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, AcceptRequestWithPublicOOBInvitation, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if args.Invitation == nil {
		logutil.LogDebug(logger, CommandName, AcceptRequestWithPublicOOBInvitation, errEmptyInvitation)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyInvitation))
	}

	if args.To == nil {
		logutil.LogDebug(logger, CommandName, AcceptRequestWithPublicOOBInvitation, errEmptyTo)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyTo))
	}

	if err := c.client.AcceptRequestWithPublicOOBInvitation(args.PIID, args.Invitation, args.To); err != nil {
		logutil.LogError(logger, CommandName, AcceptRequestWithPublicOOBInvitation, err.Error())
		return command.NewExecuteError(AcceptRequestWithPublicOOBInvitationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptRequestWithPublicOOBInvitationResponse{}, logger)

	logutil.LogDebug(logger, CommandName, AcceptRequestWithPublicOOBInvitation, successString)

	return nil
}

// AcceptRequestWithRecipients is used when the introducer does not have a published out-of-band message on hand
// but he is willing to introduce agents to each other.
func (c *Command) AcceptRequestWithRecipients(rw io.Writer, req io.Reader) command.Error {
	var args AcceptRequestWithRecipientsArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, AcceptRequestWithRecipients, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, AcceptRequestWithRecipients, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if args.Recipient == nil {
		logutil.LogDebug(logger, CommandName, AcceptRequestWithRecipients, errEmptyRecipient)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyRecipient))
	}

	if args.To == nil {
		logutil.LogDebug(logger, CommandName, AcceptRequestWithRecipients, errEmptyTo)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyTo))
	}

	if err := c.client.AcceptRequestWithRecipients(args.PIID, args.To, args.Recipient); err != nil {
		logutil.LogError(logger, CommandName, AcceptRequestWithRecipients, err.Error())
		return command.NewExecuteError(AcceptRequestWithRecipientsErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptRequestWithRecipientsResponse{}, logger)

	logutil.LogDebug(logger, CommandName, AcceptRequestWithRecipients, successString)

	return nil
}

// DeclineProposal is used to reject the proposal.
func (c *Command) DeclineProposal(rw io.Writer, req io.Reader) command.Error {
	var args DeclineProposalArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, DeclineProposal, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, DeclineProposal, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.DeclineProposal(args.PIID, args.Reason); err != nil {
		logutil.LogError(logger, CommandName, DeclineProposal, err.Error())
		return command.NewExecuteError(DeclineProposalErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeclineProposalResponse{}, logger)

	logutil.LogDebug(logger, CommandName, DeclineProposal, successString)

	return nil
}

// DeclineRequest is used to reject the request.
func (c *Command) DeclineRequest(rw io.Writer, req io.Reader) command.Error {
	var args DeclineRequestArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, DeclineRequest, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, DeclineRequest, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.DeclineRequest(args.PIID, args.Reason); err != nil {
		logutil.LogError(logger, CommandName, DeclineRequest, err.Error())
		return command.NewExecuteError(DeclineRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeclineRequestResponse{}, logger)

	logutil.LogDebug(logger, CommandName, DeclineRequest, successString)

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
