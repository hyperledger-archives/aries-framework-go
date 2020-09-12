/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/webnotifier"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
)

var logger = log.New("aries-framework/controller/issuecredential")

const (
	// InvalidRequestErrorCode is typically a code for validation errors
	// for invalid issue credential controller requests.
	InvalidRequestErrorCode = command.Code(iota + command.IssueCredential)
	// AcceptProposalErrorCode is for failures in accept proposal command.
	AcceptProposalErrorCode
	// AcceptOfferErrorCode is for failures in accept offer command.
	AcceptOfferErrorCode
	// AcceptRequestErrorCode is for failures in accept request command.
	AcceptRequestErrorCode
	// AcceptCredentialErrorCode is for failures in accept credential command.
	AcceptCredentialErrorCode
	// AcceptProblemReportErrorCode is for failures in accept problem report command.
	AcceptProblemReportErrorCode
	// NegotiateProposalErrorCode is for failures in negotiate proposal command.
	NegotiateProposalErrorCode
	// DeclineProposalErrorCode is for failures in decline proposal command.
	DeclineProposalErrorCode
	// DeclineOfferErrorCode is for failures in decline offer command.
	DeclineOfferErrorCode
	// DeclineRequestErrorCode is for failures in decline request command.
	DeclineRequestErrorCode
	// DeclineCredentialErrorCode is for failures in decline credential command.
	DeclineCredentialErrorCode
	// SendProposalErrorCode failures in send proposal command.
	SendProposalErrorCode
	// SendOfferErrorCode failures in send offer command.
	SendOfferErrorCode
	// SendRequestErrorCode failures in send request command.
	SendRequestErrorCode
	// ActionsErrorCode failures in actions command.
	ActionsErrorCode
)

// constants for issue credential commands.
const (
	// command name.
	CommandName = "issuecredential"

	Actions             = "Actions"
	SendOffer           = "SendOffer"
	SendProposal        = "SendProposal"
	SendRequest         = "SendRequest"
	AcceptProposal      = "AcceptProposal"
	DeclineProposal     = "DeclineProposal"
	AcceptOffer         = "AcceptOffer"
	DeclineOffer        = "DeclineOffer"
	NegotiateProposal   = "NegotiateProposal"
	AcceptRequest       = "AcceptRequest"
	DeclineRequest      = "DeclineRequest"
	AcceptCredential    = "AcceptCredential"
	DeclineCredential   = "DeclineCredential"
	AcceptProblemReport = "AcceptProblemReport"
)

const (
	// error messages.
	errEmptyPIID              = "empty PIID"
	errEmptyMyDID             = "empty MyDID"
	errEmptyTheirDID          = "empty TheirDID"
	errEmptyOfferCredential   = "empty OfferCredential"
	errEmptyIssueCredential   = "empty IssueCredential"
	errEmptyProposeCredential = "empty ProposeCredential"
	errEmptyRequestCredential = "empty RequestCredential"
	// log constants.
	successString = "success"

	_actions = "_actions"
	_states  = "_states"
)

// Command is controller command for issue credential.
type Command struct {
	client *issuecredential.Client
}

// New returns new issue credential controller command instance.
func New(ctx issuecredential.Provider, notifier command.Notifier) (*Command, error) {
	client, err := issuecredential.New(ctx)
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
		cmdutil.NewCommandHandler(CommandName, Actions, c.Actions),
		cmdutil.NewCommandHandler(CommandName, SendOffer, c.SendOffer),
		cmdutil.NewCommandHandler(CommandName, SendProposal, c.SendProposal),
		cmdutil.NewCommandHandler(CommandName, SendRequest, c.SendRequest),
		cmdutil.NewCommandHandler(CommandName, AcceptProposal, c.AcceptProposal),
		cmdutil.NewCommandHandler(CommandName, DeclineProposal, c.DeclineProposal),
		cmdutil.NewCommandHandler(CommandName, AcceptOffer, c.AcceptOffer),
		cmdutil.NewCommandHandler(CommandName, AcceptProblemReport, c.AcceptProblemReport),
		cmdutil.NewCommandHandler(CommandName, DeclineOffer, c.DeclineOffer),
		cmdutil.NewCommandHandler(CommandName, NegotiateProposal, c.NegotiateProposal),
		cmdutil.NewCommandHandler(CommandName, AcceptRequest, c.AcceptRequest),
		cmdutil.NewCommandHandler(CommandName, DeclineRequest, c.DeclineRequest),
		cmdutil.NewCommandHandler(CommandName, AcceptCredential, c.AcceptCredential),
		cmdutil.NewCommandHandler(CommandName, DeclineCredential, c.DeclineCredential),
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

// SendOffer is used by the Issuer to send an offer.
// nolint: dupl
func (c *Command) SendOffer(rw io.Writer, req io.Reader) command.Error {
	var args SendOfferArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, SendOffer, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.MyDID == "" {
		logutil.LogDebug(logger, CommandName, SendOffer, errEmptyMyDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyMyDID))
	}

	if args.TheirDID == "" {
		logutil.LogDebug(logger, CommandName, SendOffer, errEmptyTheirDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyTheirDID))
	}

	if args.OfferCredential == nil {
		logutil.LogDebug(logger, CommandName, SendOffer, errEmptyOfferCredential)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyOfferCredential))
	}

	piid, err := c.client.SendOffer(args.OfferCredential, args.MyDID, args.TheirDID)
	if err != nil {
		logutil.LogError(logger, CommandName, SendOffer, err.Error())
		return command.NewExecuteError(SendOfferErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendOfferResponse{PIID: piid}, logger)

	logutil.LogDebug(logger, CommandName, SendOffer, successString)

	return nil
}

// SendProposal is used by the Holder to send a proposal.
// nolint: dupl
func (c *Command) SendProposal(rw io.Writer, req io.Reader) command.Error {
	var args SendProposalArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, SendProposal, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.MyDID == "" {
		logutil.LogDebug(logger, CommandName, SendProposal, errEmptyMyDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyMyDID))
	}

	if args.TheirDID == "" {
		logutil.LogDebug(logger, CommandName, SendProposal, errEmptyTheirDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyTheirDID))
	}

	if args.ProposeCredential == nil {
		logutil.LogDebug(logger, CommandName, SendProposal, errEmptyProposeCredential)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyProposeCredential))
	}

	piid, err := c.client.SendProposal(args.ProposeCredential, args.MyDID, args.TheirDID)
	if err != nil {
		logutil.LogError(logger, CommandName, SendProposal, err.Error())
		return command.NewExecuteError(SendProposalErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendProposalResponse{PIID: piid}, logger)

	logutil.LogDebug(logger, CommandName, SendProposal, successString)

	return nil
}

// SendRequest is used by the Holder to send a request.
// nolint: dupl
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

	if args.RequestCredential == nil {
		logutil.LogDebug(logger, CommandName, SendRequest, errEmptyRequestCredential)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyRequestCredential))
	}

	piid, err := c.client.SendRequest(args.RequestCredential, args.MyDID, args.TheirDID)
	if err != nil {
		logutil.LogError(logger, CommandName, SendRequest, err.Error())
		return command.NewExecuteError(SendRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendRequestResponse{PIID: piid}, logger)

	logutil.LogDebug(logger, CommandName, SendRequest, successString)

	return nil
}

// AcceptProposal is used when the Issuer is willing to accept the proposal.
// nolint: dupl
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

	if args.OfferCredential == nil {
		logutil.LogDebug(logger, CommandName, AcceptProposal, errEmptyOfferCredential)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyOfferCredential))
	}

	if err := c.client.AcceptProposal(args.PIID, args.OfferCredential); err != nil {
		logutil.LogError(logger, CommandName, AcceptProposal, err.Error())
		return command.NewExecuteError(AcceptProposalErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptProposalResponse{}, logger)

	logutil.LogDebug(logger, CommandName, AcceptProposal, successString)

	return nil
}

// NegotiateProposal is used when the Holder wants to negotiate about an offer he received.
// nolint: dupl
func (c *Command) NegotiateProposal(rw io.Writer, req io.Reader) command.Error {
	var args NegotiateProposalArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, NegotiateProposal, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, NegotiateProposal, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if args.ProposeCredential == nil {
		logutil.LogDebug(logger, CommandName, NegotiateProposal, errEmptyProposeCredential)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyProposeCredential))
	}

	if err := c.client.NegotiateProposal(args.PIID, args.ProposeCredential); err != nil {
		logutil.LogError(logger, CommandName, NegotiateProposal, err.Error())
		return command.NewExecuteError(NegotiateProposalErrorCode, err)
	}

	command.WriteNillableResponse(rw, &NegotiateProposalResponse{}, logger)

	logutil.LogDebug(logger, CommandName, NegotiateProposal, successString)

	return nil
}

// DeclineProposal is used when the Issuer does not want to accept the proposal.
// nolint: dupl
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

// AcceptOffer is used when the Holder is willing to accept the offer.
// nolint: dupl
func (c *Command) AcceptOffer(rw io.Writer, req io.Reader) command.Error {
	var args AcceptOfferArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, AcceptOffer, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, AcceptOffer, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.AcceptOffer(args.PIID); err != nil {
		logutil.LogError(logger, CommandName, AcceptOffer, err.Error())
		return command.NewExecuteError(AcceptOfferErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptOfferResponse{}, logger)

	logutil.LogDebug(logger, CommandName, AcceptOffer, successString)

	return nil
}

// AcceptProblemReport is used for accepting problem report.
// nolint: dupl
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

// DeclineOffer is used when the Holder does not want to accept the offer.
// nolint: dupl
func (c *Command) DeclineOffer(rw io.Writer, req io.Reader) command.Error {
	var args DeclineOfferArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, DeclineOffer, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, DeclineOffer, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.DeclineOffer(args.PIID, args.Reason); err != nil {
		logutil.LogError(logger, CommandName, DeclineOffer, err.Error())
		return command.NewExecuteError(DeclineOfferErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeclineOfferResponse{}, logger)

	logutil.LogDebug(logger, CommandName, DeclineOffer, successString)

	return nil
}

// AcceptRequest is used when the Issuer is willing to accept the request.
// nolint: dupl
func (c *Command) AcceptRequest(rw io.Writer, req io.Reader) command.Error {
	var request AcceptRequestArgs

	if err := json.NewDecoder(req).Decode(&request); err != nil {
		logutil.LogInfo(logger, CommandName, AcceptRequest, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.PIID == "" {
		logutil.LogDebug(logger, CommandName, AcceptRequest, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if request.IssueCredential == nil {
		logutil.LogDebug(logger, CommandName, AcceptRequest, errEmptyIssueCredential)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyIssueCredential))
	}

	if err := c.client.AcceptRequest(request.PIID, request.IssueCredential); err != nil {
		logutil.LogError(logger, CommandName, AcceptRequest, err.Error())
		return command.NewExecuteError(AcceptRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptRequestResponse{}, logger)

	logutil.LogDebug(logger, CommandName, AcceptRequest, successString)

	return nil
}

// DeclineRequest is used when the Issuer does not want to accept the request.
// nolint: dupl
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

// AcceptCredential is used when the Holder is willing to accept the IssueCredential.
// nolint: dupl
func (c *Command) AcceptCredential(rw io.Writer, req io.Reader) command.Error {
	var args AcceptCredentialArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, AcceptCredential, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, AcceptCredential, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.AcceptCredential(args.PIID, args.Names...); err != nil {
		logutil.LogError(logger, CommandName, AcceptCredential, err.Error())
		return command.NewExecuteError(AcceptCredentialErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptCredentialResponse{}, logger)

	logutil.LogDebug(logger, CommandName, AcceptCredential, successString)

	return nil
}

// DeclineCredential is used when the Holder does not want to accept the IssueCredential.
// nolint: dupl
func (c *Command) DeclineCredential(rw io.Writer, req io.Reader) command.Error {
	var args DeclineCredentialArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, CommandName, DeclineCredential, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, CommandName, DeclineCredential, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.DeclineCredential(args.PIID, args.Reason); err != nil {
		logutil.LogError(logger, CommandName, DeclineCredential, err.Error())
		return command.NewExecuteError(DeclineCredentialErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeclineCredentialResponse{}, logger)

	logutil.LogDebug(logger, CommandName, DeclineCredential, successString)

	return nil
}
