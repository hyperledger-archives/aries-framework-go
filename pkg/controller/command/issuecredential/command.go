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
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
)

var logger = log.New("aries-framework/controller/issuecredential")

const (
	// InvalidRequestErrorCode is typically a code for validation errors
	// for invalid issue credential controller requests
	InvalidRequestErrorCode = command.Code(iota + command.IssueCredential)
	// AcceptProposalErrorCode is for failures in accept proposal command
	AcceptProposalErrorCode
	// AcceptOfferErrorCode is for failures in accept offer command
	AcceptOfferErrorCode
	// AcceptRequestErrorCode is for failures in accept request command
	AcceptRequestErrorCode
	// AcceptCredentialErrorCode is for failures in accept credential command
	AcceptCredentialErrorCode
	// NegotiateProposalErrorCode is for failures in negotiate proposal command
	NegotiateProposalErrorCode
	// DeclineProposalErrorCode is for failures in decline proposal command
	DeclineProposalErrorCode
	// DeclineOfferErrorCode is for failures in decline offer command
	DeclineOfferErrorCode
	// DeclineRequestErrorCode is for failures in decline request command
	DeclineRequestErrorCode
	// DeclineCredentialErrorCode is for failures in decline credential command
	DeclineCredentialErrorCode
	// SendProposalErrorCode failures in send proposal command
	SendProposalErrorCode
	// SendOfferErrorCode failures in send offer command
	SendOfferErrorCode
	// SendRequestErrorCode failures in send request command
	SendRequestErrorCode
	// ActionsErrorCode failures in actions command
	ActionsErrorCode
)

const (
	// command name
	commandName = "issuecredential"

	actions           = "Actions"
	sendOffer         = "SendOffer"
	sendProposal      = "SendProposal"
	sendRequest       = "SendRequest"
	acceptProposal    = "AcceptProposal"
	declineProposal   = "DeclineProposal"
	acceptOffer       = "AcceptOffer"
	declineOffer      = "DeclineOffer"
	negotiateProposal = "NegotiateProposal"
	acceptRequest     = "AcceptRequest"
	declineRequest    = "DeclineRequest"
	acceptCredential  = "AcceptCredential"
	declineCredential = "DeclineCredential"
)

const (
	// error messages
	errEmptyPIID              = "empty PIID"
	errEmptyMyDID             = "empty MyDID"
	errEmptyTheirDID          = "empty TheirDID"
	errEmptyOfferCredential   = "empty OfferCredential"
	errEmptyIssueCredential   = "empty IssueCredential"
	errEmptyProposeCredential = "empty ProposeCredential"
	errEmptyRequestCredential = "empty RequestCredential"
	// log constants
	successString = "success"
)

// Command is controller command for issue credential
type Command struct {
	client *issuecredential.Client
}

// New returns new issue credential controller command instance
func New(ctx issuecredential.Provider) (*Command, error) {
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
		cmdutil.NewCommandHandler(commandName, sendOffer, c.SendOffer),
		cmdutil.NewCommandHandler(commandName, sendProposal, c.SendProposal),
		cmdutil.NewCommandHandler(commandName, sendRequest, c.SendRequest),
		cmdutil.NewCommandHandler(commandName, acceptProposal, c.AcceptProposal),
		cmdutil.NewCommandHandler(commandName, declineProposal, c.DeclineProposal),
		cmdutil.NewCommandHandler(commandName, acceptOffer, c.AcceptOffer),
		cmdutil.NewCommandHandler(commandName, declineOffer, c.DeclineOffer),
		cmdutil.NewCommandHandler(commandName, negotiateProposal, c.NegotiateProposal),
		cmdutil.NewCommandHandler(commandName, acceptRequest, c.AcceptRequest),
		cmdutil.NewCommandHandler(commandName, declineRequest, c.DeclineRequest),
		cmdutil.NewCommandHandler(commandName, acceptCredential, c.AcceptCredential),
		cmdutil.NewCommandHandler(commandName, declineCredential, c.DeclineCredential),
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

// SendOffer is used by the Issuer to send an offer.
// nolint: dupl
func (c *Command) SendOffer(rw io.Writer, req io.Reader) command.Error {
	var args SendOfferArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, sendOffer, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.MyDID == "" {
		logutil.LogDebug(logger, commandName, sendOffer, errEmptyMyDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyMyDID))
	}

	if args.TheirDID == "" {
		logutil.LogDebug(logger, commandName, sendOffer, errEmptyTheirDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyTheirDID))
	}

	if args.OfferCredential == nil {
		logutil.LogDebug(logger, commandName, sendOffer, errEmptyOfferCredential)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyOfferCredential))
	}

	if err := c.client.SendOffer(args.OfferCredential, args.MyDID, args.TheirDID); err != nil {
		logutil.LogError(logger, commandName, sendOffer, err.Error())
		return command.NewExecuteError(SendOfferErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendOfferResponse{}, logger)

	logutil.LogDebug(logger, commandName, sendOffer, successString)

	return nil
}

// SendProposal is used by the Holder to send a proposal.
// nolint: dupl
func (c *Command) SendProposal(rw io.Writer, req io.Reader) command.Error {
	var args SendProposalArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, sendProposal, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.MyDID == "" {
		logutil.LogDebug(logger, commandName, sendProposal, errEmptyMyDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyMyDID))
	}

	if args.TheirDID == "" {
		logutil.LogDebug(logger, commandName, sendProposal, errEmptyTheirDID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyTheirDID))
	}

	if args.ProposeCredential == nil {
		logutil.LogDebug(logger, commandName, sendProposal, errEmptyProposeCredential)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyProposeCredential))
	}

	if err := c.client.SendProposal(args.ProposeCredential, args.MyDID, args.TheirDID); err != nil {
		logutil.LogError(logger, commandName, sendProposal, err.Error())
		return command.NewExecuteError(SendProposalErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendProposalResponse{}, logger)

	logutil.LogDebug(logger, commandName, sendProposal, successString)

	return nil
}

// SendRequest is used by the Holder to send a request.
// nolint: dupl
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

	if args.RequestCredential == nil {
		logutil.LogDebug(logger, commandName, sendRequest, errEmptyRequestCredential)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyRequestCredential))
	}

	if err := c.client.SendRequest(args.RequestCredential, args.MyDID, args.TheirDID); err != nil {
		logutil.LogError(logger, commandName, sendRequest, err.Error())
		return command.NewExecuteError(SendRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendRequestResponse{}, logger)

	logutil.LogDebug(logger, commandName, sendRequest, successString)

	return nil
}

// AcceptProposal is used when the Issuer is willing to accept the proposal.
// nolint: dupl
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

	if args.OfferCredential == nil {
		logutil.LogDebug(logger, commandName, acceptProposal, errEmptyOfferCredential)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyOfferCredential))
	}

	if err := c.client.AcceptProposal(args.PIID, args.OfferCredential); err != nil {
		logutil.LogError(logger, commandName, acceptProposal, err.Error())
		return command.NewExecuteError(AcceptProposalErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptProposalResponse{}, logger)

	logutil.LogDebug(logger, commandName, acceptProposal, successString)

	return nil
}

// NegotiateProposal is used when the Holder wants to negotiate about an offer he received.
// nolint: dupl
func (c *Command) NegotiateProposal(rw io.Writer, req io.Reader) command.Error {
	var args NegotiateProposalArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, negotiateProposal, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, commandName, negotiateProposal, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if args.ProposeCredential == nil {
		logutil.LogDebug(logger, commandName, negotiateProposal, errEmptyProposeCredential)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyProposeCredential))
	}

	if err := c.client.NegotiateProposal(args.PIID, args.ProposeCredential); err != nil {
		logutil.LogError(logger, commandName, negotiateProposal, err.Error())
		return command.NewExecuteError(NegotiateProposalErrorCode, err)
	}

	command.WriteNillableResponse(rw, &NegotiateProposalResponse{}, logger)

	logutil.LogDebug(logger, commandName, negotiateProposal, successString)

	return nil
}

// DeclineProposal is used when the Issuer does not want to accept the proposal.
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

// AcceptOffer is used when the Holder is willing to accept the offer.
func (c *Command) AcceptOffer(rw io.Writer, req io.Reader) command.Error {
	var args AcceptOfferArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, acceptOffer, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, commandName, acceptOffer, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.AcceptOffer(args.PIID); err != nil {
		logutil.LogError(logger, commandName, acceptOffer, err.Error())
		return command.NewExecuteError(AcceptOfferErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptOfferResponse{}, logger)

	logutil.LogDebug(logger, commandName, acceptOffer, successString)

	return nil
}

// DeclineOffer is used when the Holder does not want to accept the offer.
// nolint: dupl
func (c *Command) DeclineOffer(rw io.Writer, req io.Reader) command.Error {
	var args DeclineOfferArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, declineOffer, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, commandName, declineOffer, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.DeclineOffer(args.PIID, args.Reason); err != nil {
		logutil.LogError(logger, commandName, declineOffer, err.Error())
		return command.NewExecuteError(DeclineOfferErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeclineOfferResponse{}, logger)

	logutil.LogDebug(logger, commandName, declineOffer, successString)

	return nil
}

// AcceptRequest is used when the Issuer is willing to accept the request.
// nolint: dupl
func (c *Command) AcceptRequest(rw io.Writer, req io.Reader) command.Error {
	var request AcceptRequestArgs

	if err := json.NewDecoder(req).Decode(&request); err != nil {
		logutil.LogInfo(logger, commandName, acceptRequest, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if request.PIID == "" {
		logutil.LogDebug(logger, commandName, acceptRequest, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if request.IssueCredential == nil {
		logutil.LogDebug(logger, commandName, acceptRequest, errEmptyIssueCredential)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyIssueCredential))
	}

	if err := c.client.AcceptRequest(request.PIID, request.IssueCredential); err != nil {
		logutil.LogError(logger, commandName, acceptRequest, err.Error())
		return command.NewExecuteError(AcceptRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptRequestResponse{}, logger)

	logutil.LogDebug(logger, commandName, acceptRequest, successString)

	return nil
}

// DeclineRequest is used when the Issuer does not want to accept the request.
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

// AcceptCredential is used when the Holder is willing to accept the IssueCredential.
// nolint: dupl
func (c *Command) AcceptCredential(rw io.Writer, req io.Reader) command.Error {
	var args AcceptCredentialArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, acceptCredential, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, commandName, acceptCredential, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.AcceptCredential(args.PIID, args.Names...); err != nil {
		logutil.LogError(logger, commandName, acceptCredential, err.Error())
		return command.NewExecuteError(AcceptCredentialErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptCredentialResponse{}, logger)

	logutil.LogDebug(logger, commandName, acceptCredential, successString)

	return nil
}

// DeclineCredential is used when the Holder does not want to accept the IssueCredential.
// nolint: dupl
func (c *Command) DeclineCredential(rw io.Writer, req io.Reader) command.Error {
	var args DeclineCredentialArgs

	if err := json.NewDecoder(req).Decode(&args); err != nil {
		logutil.LogInfo(logger, commandName, declineCredential, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	if args.PIID == "" {
		logutil.LogDebug(logger, commandName, declineCredential, errEmptyPIID)
		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errEmptyPIID))
	}

	if err := c.client.DeclineCredential(args.PIID, args.Reason); err != nil {
		logutil.LogError(logger, commandName, declineCredential, err.Error())
		return command.NewExecuteError(DeclineCredentialErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeclineCredentialResponse{}, logger)

	logutil.LogDebug(logger, commandName, declineCredential, successString)

	return nil
}
