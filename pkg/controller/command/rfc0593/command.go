/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rfc0593

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential/rfc0593"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
)

var logger = log.New("aries-framework/controller/rfc0593")

const (
	// BadRequestErrorCode is typically a code for validation errors
	// for invalid issue credential controller requests.
	BadRequestErrorCode = command.Code(iota + command.RFC0593)
	// RFC0593NotApplicableErrorCode indicates the message does not apply for RFC0593.
	RFC0593NotApplicableErrorCode
	// UnableToIssueCredentialErrorCode is a generic error code.
	UnableToIssueCredentialErrorCode
)

const (
	// CommandName is the name of this command.
	CommandName = "RFC0593"

	// GetCredentialSpec is the name of the command that extracts credential specifications.
	GetCredentialSpec = "GetCredentialSpec"
	// IssueCredential is the name of the command that issues a credential based on specifications.
	IssueCredential = "IssueCredential"
	// VerifyCredential is the name of the command that verifies a credential against specifications.
	VerifyCredential = "VerifyCredential"
)

// Command exposes RFC0593 commands.
type Command struct {
	provider rfc0593.Provider
}

// New returns a new Command.
func New(p rfc0593.Provider) *Command {
	return &Command{provider: p}
}

// GetHandlers returns list of all commands supported by this controller command.
func (c *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, GetCredentialSpec, c.GetCredentialSpec),
		cmdutil.NewCommandHandler(CommandName, IssueCredential, c.IssueCredential),
		cmdutil.NewCommandHandler(CommandName, VerifyCredential, c.VerifyCredential),
	}
}

// GetCredentialSpec extracts the credential specification.
func (c *Command) GetCredentialSpec(w io.Writer, r io.Reader) command.Error { // nolint:funlen
	args := &GetCredentialSpecArgs{}

	err := json.NewDecoder(r).Decode(args)
	if err != nil {
		logutil.LogError(logger, CommandName, GetCredentialSpec, err.Error())
		return command.NewValidationError(BadRequestErrorCode, err)
	}

	if len(args.Message) == 0 {
		logutil.LogError(logger, CommandName, GetCredentialSpec, "missing message")
		return command.NewValidationError(BadRequestErrorCode, errors.New("missing message"))
	}

	var (
		formats     []issuecredential.Format
		attachments []decorator.Attachment
	)

	msgType := struct {
		Type string `json:"@type"`
	}{}

	err = json.Unmarshal(args.Message, &msgType)
	if err != nil {
		errMsg := fmt.Errorf("cannot unmarshal arg message: %w", err)
		logutil.LogInfo(logger, CommandName, GetCredentialSpec, errMsg.Error())

		return command.NewValidationError(BadRequestErrorCode, errMsg)
	}

	switch msgType.Type {
	case issuecredential.ProposeCredentialMsgTypeV2:
		proposal := &issuecredential.ProposeCredentialV2{}
		err = json.Unmarshal(args.Message, proposal)
		formats = proposal.Formats
		attachments = proposal.FiltersAttach
	case issuecredential.OfferCredentialMsgTypeV2:
		offer := &issuecredential.OfferCredentialV2{}
		err = json.Unmarshal(args.Message, offer)
		formats = offer.Formats
		attachments = offer.OffersAttach
	case issuecredential.RequestCredentialMsgTypeV2:
		request := &issuecredential.RequestCredentialV2{}
		err = json.Unmarshal(args.Message, request)
		formats = request.Formats
		attachments = request.RequestsAttach
	default:
		err = fmt.Errorf("invalid msg type: %s", msgType.Type)
	}

	if err != nil {
		errMsg := fmt.Errorf("failed to unmarshal payload: %w", err)
		logutil.LogError(logger, CommandName, GetCredentialSpec, errMsg.Error())

		return command.NewValidationError(BadRequestErrorCode, errMsg)
	}

	spec, err := rfc0593.GetCredentialSpec(c.provider, formats, attachments)
	if errors.Is(err, rfc0593.ErrRFC0593NotApplicable) {
		logutil.LogError(logger, CommandName, GetCredentialSpec, err.Error())

		return command.NewValidationError(RFC0593NotApplicableErrorCode, err)
	}

	if err != nil {
		logutil.LogError(logger, CommandName, GetCredentialSpec, err.Error())

		return command.NewValidationError(BadRequestErrorCode, err)
	}

	command.WriteNillableResponse(w, &GetCredentialSpecResponse{Spec: spec}, logger)
	logutil.LogDebug(logger, CommandName, GetCredentialSpec, "success")

	return nil
}

// IssueCredential issues a credential based on a credential spec.
func (c *Command) IssueCredential(w io.Writer, r io.Reader) command.Error {
	args := &IssueCredentialArgs{}

	err := json.NewDecoder(r).Decode(args)
	if err != nil {
		logutil.LogError(logger, CommandName, IssueCredential, err.Error())

		return command.NewValidationError(BadRequestErrorCode, err)
	}

	if args.Spec.Options == nil {
		errMsg := errors.New("missing spec options")
		logutil.LogError(logger, CommandName, IssueCredential, errMsg.Error())

		return command.NewValidationError(BadRequestErrorCode, errMsg)
	}

	msg, err := rfc0593.CreateIssueCredentialMsg(c.provider, &args.Spec)
	if err != nil {
		errMsg := fmt.Errorf("failed to issue credential: %w", err)
		logutil.LogError(logger, CommandName, IssueCredential, errMsg.Error())

		return command.NewExecuteError(UnableToIssueCredentialErrorCode, errMsg)
	}

	command.WriteNillableResponse(w, &IssueCredentialResponse{IssueCredential: msg}, logger)
	logutil.LogDebug(logger, CommandName, IssueCredential, "success")

	return nil
}

// VerifyCredential verifies a credential against a spec.
func (c *Command) VerifyCredential(w io.Writer, r io.Reader) command.Error {
	args := &VerifyCredentialArgs{}

	err := json.NewDecoder(r).Decode(args)
	if err != nil {
		logutil.LogError(logger, CommandName, VerifyCredential, err.Error())

		return command.NewValidationError(BadRequestErrorCode, err)
	}

	vc, err := verifiable.ParseCredential(
		args.Credential,
		verifiable.WithJSONLDDocumentLoader(c.provider.JSONLDDocumentLoader()),
		verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(c.provider.VDRegistry()).PublicKeyFetcher()),
	)
	if err != nil {
		logutil.LogError(logger, CommandName, VerifyCredential, fmt.Sprintf("failed to parse vc: %s", err.Error()))

		return command.NewValidationError(BadRequestErrorCode, fmt.Errorf("failed to parse vc: %w", err))
	}

	err = rfc0593.ValidateVCMatchesSpecOptions(vc, args.Spec.Options)
	if err != nil {
		errMsg := fmt.Errorf("verification failed: %w", err)
		logutil.LogError(logger, CommandName, VerifyCredential, errMsg.Error())

		return command.NewValidationError(BadRequestErrorCode, errMsg)
	}

	command.WriteNillableResponse(w, nil, logger)
	logutil.LogDebug(logger, CommandName, VerifyCredential, "success")

	return nil
}
