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
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential/rfc0593"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/webnotifier"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	protocol "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
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
	SendOfferV3         = "SendOfferV3"
	SendProposal        = "SendProposal"
	SendProposalV3      = "SendProposalV3"
	SendRequest         = "SendRequest"
	SendRequestV3       = "SendRequestV3"
	AcceptProposal      = "AcceptProposal"
	AcceptProposalV3    = "AcceptProposalV3"
	DeclineProposal     = "DeclineProposal"
	AcceptOffer         = "AcceptOffer"
	DeclineOffer        = "DeclineOffer"
	NegotiateProposal   = "NegotiateProposal"
	NegotiateProposalV3 = "NegotiateProposalV3"
	AcceptRequest       = "AcceptRequest"
	AcceptRequestV3     = "AcceptRequestV3"
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
	errMissingConnection      = "no connection for given connection ID"
	// log constants.
	successString = "success"

	_actions = "_actions"
	_states  = "_states"
)

// Options contains configuration options.
type Options struct {
	rfc0593Provider rfc0593.Provider
}

// Option modifies Options.
type Option func(*Options)

// WithAutoExecuteRFC0593 enables RFC0593.
func WithAutoExecuteRFC0593(p rfc0593.Provider) Option {
	return func(o *Options) {
		o.rfc0593Provider = p
	}
}

// Provider contains dependencies for the issuecredential protocol and is typically created by using aries.Context().
type Provider interface {
	Service(id string) (interface{}, error)
	ConnectionLookup() *connection.Lookup
}

// Command is controller command for issue credential.
type Command struct {
	client *issuecredential.Client
	lookup *connection.Lookup
}

// New returns new issue credential controller command instance.
func New(ctx Provider, notifier command.Notifier, options ...Option) (*Command, error) {
	opts := &Options{}

	for i := range options {
		options[i](opts)
	}

	client, err := issuecredential.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot create a client: %w", err)
	}

	// creates state channel
	states := make(chan service.StateMsg)
	// registers state channel to listen for events
	if err = client.RegisterMsgEvent(states); err != nil {
		return nil, fmt.Errorf("register msg event: %w", err)
	}

	obs := webnotifier.NewObserver(notifier)
	obs.RegisterStateMsg(protocol.Name+_states, states)

	// creates action channel
	actions := make(chan service.DIDCommAction)
	// registers action channel to listen for events
	if err = client.RegisterActionEvent(actions); err != nil {
		return nil, fmt.Errorf("register action event: %w", err)
	}

	if opts.rfc0593Provider != nil {
		mw, err := rfc0593.NewMiddleware(opts.rfc0593Provider)
		if err != nil {
			return nil, fmt.Errorf("failed to init rfc0593 middleware: %w", err)
		}

		err = rfc0593.RegisterMiddleware(mw, ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to register rfc0593 middleware: %w", err)
		}

		next := make(chan service.DIDCommAction)

		go rfc0593.AutoExecute(opts.rfc0593Provider, next)(actions)

		obs.RegisterAction(protocol.Name+_actions, next)
	} else {
		obs.RegisterAction(protocol.Name+_actions, actions)
	}

	return &Command{
		client: client,
		lookup: ctx.ConnectionLookup(),
	}, nil
}

// GetHandlers returns list of all commands supported by this controller command.
func (c *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, Actions, c.Actions),
		cmdutil.NewCommandHandler(CommandName, SendOffer, c.SendOffer),
		cmdutil.NewCommandHandler(CommandName, SendOfferV3, c.SendOffer),
		cmdutil.NewCommandHandler(CommandName, SendProposal, c.SendProposal),
		cmdutil.NewCommandHandler(CommandName, SendProposalV3, c.SendProposal),
		cmdutil.NewCommandHandler(CommandName, SendRequest, c.SendRequest),
		cmdutil.NewCommandHandler(CommandName, SendRequestV3, c.SendRequest),
		cmdutil.NewCommandHandler(CommandName, AcceptProposal, c.AcceptProposal),
		cmdutil.NewCommandHandler(CommandName, AcceptProposalV3, c.AcceptProposal),
		cmdutil.NewCommandHandler(CommandName, DeclineProposal, c.DeclineProposal),
		cmdutil.NewCommandHandler(CommandName, AcceptOffer, c.AcceptOffer),
		cmdutil.NewCommandHandler(CommandName, AcceptProblemReport, c.AcceptProblemReport),
		cmdutil.NewCommandHandler(CommandName, DeclineOffer, c.DeclineOffer),
		cmdutil.NewCommandHandler(CommandName, NegotiateProposal, c.NegotiateProposal),
		cmdutil.NewCommandHandler(CommandName, NegotiateProposalV3, c.NegotiateProposal),
		cmdutil.NewCommandHandler(CommandName, AcceptRequest, c.AcceptRequest),
		cmdutil.NewCommandHandler(CommandName, AcceptRequestV3, c.AcceptRequest),
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

	conn, err := c.lookup.GetConnectionRecordByDIDs(args.MyDID, args.TheirDID)
	if err != nil {
		logutil.LogDebug(logger, CommandName, SendOffer, errMissingConnection)

		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errMissingConnection))
	}

	piid, err := c.client.SendOffer(args.OfferCredential, conn)
	if err != nil {
		logutil.LogError(logger, CommandName, SendOffer, err.Error())
		return command.NewExecuteError(SendOfferErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendOfferResponse{PIID: piid}, logger)

	logutil.LogDebug(logger, CommandName, SendOffer, successString)

	return nil
}

// SendProposal is used by the Holder to send a proposal.
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

	conn, err := c.lookup.GetConnectionRecordByDIDs(args.MyDID, args.TheirDID)
	if err != nil {
		logutil.LogDebug(logger, CommandName, SendProposal, errMissingConnection)

		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errMissingConnection))
	}

	piid, err := c.client.SendProposal(args.ProposeCredential, conn)
	if err != nil {
		logutil.LogError(logger, CommandName, SendProposal, err.Error())
		return command.NewExecuteError(SendProposalErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendProposalResponse{PIID: piid}, logger)

	logutil.LogDebug(logger, CommandName, SendProposal, successString)

	return nil
}

// SendRequest is used by the Holder to send a request.
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

	conn, err := c.lookup.GetConnectionRecordByDIDs(args.MyDID, args.TheirDID)
	if err != nil {
		logutil.LogDebug(logger, CommandName, SendRequest, errMissingConnection)

		return command.NewValidationError(InvalidRequestErrorCode, errors.New(errMissingConnection))
	}

	piid, err := c.client.SendRequest(args.RequestCredential, conn)
	if err != nil {
		logutil.LogError(logger, CommandName, SendRequest, err.Error())
		return command.NewExecuteError(SendRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SendRequestResponse{PIID: piid}, logger)

	logutil.LogDebug(logger, CommandName, SendRequest, successString)

	return nil
}

// AcceptProposal is used when the Issuer is willing to accept the proposal.
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

	if err := c.client.DeclineProposal(args.PIID, args.Reason,
		issuecredential.RequestRedirect(args.RedirectURL)); err != nil {
		logutil.LogError(logger, CommandName, DeclineProposal, err.Error())
		return command.NewExecuteError(DeclineProposalErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeclineProposalResponse{}, logger)

	logutil.LogDebug(logger, CommandName, DeclineProposal, successString)

	return nil
}

// AcceptOffer is used when the Holder is willing to accept the offer.
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

	if err := c.client.AcceptOffer(args.PIID, &issuecredential.RequestCredential{}); err != nil {
		logutil.LogError(logger, CommandName, AcceptOffer, err.Error())
		return command.NewExecuteError(AcceptOfferErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptOfferResponse{}, logger)

	logutil.LogDebug(logger, CommandName, AcceptOffer, successString)

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

// DeclineOffer is used when the Holder does not want to accept the offer.
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

	if err := c.client.DeclineRequest(args.PIID, args.Reason,
		issuecredential.RequestRedirect(args.RedirectURL)); err != nil {
		logutil.LogError(logger, CommandName, DeclineRequest, err.Error())
		return command.NewExecuteError(DeclineRequestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeclineRequestResponse{}, logger)

	logutil.LogDebug(logger, CommandName, DeclineRequest, successString)

	return nil
}

// AcceptCredential is used when the Holder is willing to accept the IssueCredential.
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

	opts := []issuecredential.AcceptCredentialOptions{
		issuecredential.AcceptByFriendlyNames(args.Names...),
	}

	if args.SkipStore {
		opts = append(opts, issuecredential.AcceptBySkippingStorage())
	}

	if err := c.client.AcceptCredential(args.PIID, opts...); err != nil {
		logutil.LogError(logger, CommandName, AcceptCredential, err.Error())
		return command.NewExecuteError(AcceptCredentialErrorCode, err)
	}

	command.WriteNillableResponse(rw, &AcceptCredentialResponse{}, logger)

	logutil.LogDebug(logger, CommandName, AcceptCredential, successString)

	return nil
}

// DeclineCredential is used when the Holder does not want to accept the IssueCredential.
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
