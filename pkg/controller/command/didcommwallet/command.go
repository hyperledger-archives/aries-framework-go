/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didcommwallet

import (
	"encoding/json"
	"io"
	"time"

	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/vcwallet"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

var logger = log.New("aries-framework/command/didcommwallet")

// Error codes.
const (
	// InvalidRequestErrorCode is typically a code for invalid requests.
	InvalidRequestErrorCode = command.Code(iota + command.VCWallet)

	// DIDConnectErrorCode for errors while performing DID connect in wallet.
	DIDConnectErrorCode

	// ProposePresentationErrorCode for errors while proposing presentation.
	ProposePresentationErrorCode

	// PresentProofErrorCode for errors while presenting proof from wallet.
	PresentProofErrorCode

	// ProposeCredentialErrorCode for errors while proposing credential from wallet.
	ProposeCredentialErrorCode

	// RequestCredentialErrorCode for errors while request credential from wallet for issue credential protocol.
	RequestCredentialErrorCode
)

// All command operations.
const (
	// command methods.
	ConnectMethod             = "Connect"
	ProposePresentationMethod = "ProposePresentation"
	PresentProofMethod        = "PresentProof"
	ProposeCredentialMethod   = "ProposeCredential"
	RequestCredentialMethod   = "RequestCredential"
)

// miscellaneous constants for the vc wallet command controller.
const (
	// log constants.
	logSuccess         = "success"
	logUserIDKey       = "userID"
	connectionIDString = "connectionID"
	invitationIDString = "invitationID"
	LabelString        = "label"
)

// AuthCapabilityProvider is for providing Authorization Capabilities (ZCAP-LD) feature for
// wallet's EDV and WebKMS components.
type AuthCapabilityProvider = vcwallet.AuthCapabilityProvider

// HTTPHeaderSigner is for http header signing, typically used for zcapld functionality.
type HTTPHeaderSigner = vcwallet.HTTPHeaderSigner

// Config contains properties to customize verifiable credential wallet controller.
// All properties of this config are optional, but they can be used to customize wallet's webkms and edv client's.
type Config = vcwallet.Config

// provider contains dependencies for the verifiable credential wallet command controller
// and is typically created by using aries.Context().
type provider interface {
	StorageProvider() storage.Provider
	VDRegistry() vdr.Registry
	Crypto() crypto.Crypto
	JSONLDDocumentLoader() ld.DocumentLoader
	MediaTypeProfiles() []string
	didCommProvider // to be used only if wallet needs to be participated in DIDComm.
}

// didCommProvider to be used only if wallet needs to be participated in DIDComm operation.
// TODO: using wallet KMS instead of provider KMS.
// TODO: reconcile Protocol storage with wallet store.
type didCommProvider interface {
	KMS() kms.KeyManager
	ServiceEndpoint() string
	ProtocolStateStorageProvider() storage.Provider
	Service(id string) (interface{}, error)
	KeyType() kms.KeyType
	KeyAgreementType() kms.KeyType
}

// Command extends vcwallet.Command to add didComm functionality.
type Command struct {
	*vcwallet.Command
	ctx provider
}

// New returns new verifiable credential wallet controller command instance.
func New(p provider, config *Config) *Command {
	cmd := &Command{
		Command: vcwallet.New(p, config),
		ctx:     p,
	}

	return cmd
}

// GetHandlers returns list of all commands supported by this controller command.
func (o *Command) GetHandlers() []command.Handler {
	return append(o.Command.GetHandlers(),
		cmdutil.NewCommandHandler(vcwallet.CommandName, ConnectMethod, o.Connect),
		cmdutil.NewCommandHandler(vcwallet.CommandName, ProposePresentationMethod, o.ProposePresentation),
		cmdutil.NewCommandHandler(vcwallet.CommandName, PresentProofMethod, o.PresentProof),
		cmdutil.NewCommandHandler(vcwallet.CommandName, ProposeCredentialMethod, o.ProposeCredential),
		cmdutil.NewCommandHandler(vcwallet.CommandName, RequestCredentialMethod, o.RequestCredential),
	)
}

// Connect accepts out-of-band invitations and performs DID exchange.
func (o *Command) Connect(rw io.Writer, req io.Reader) command.Error {
	request := &ConnectRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, ConnectMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, ConnectMethod, err.Error())

		return command.NewExecuteError(DIDConnectErrorCode, err)
	}

	didComm, err := wallet.NewDidComm(vcWallet, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, ConnectMethod, err.Error())

		return command.NewExecuteError(DIDConnectErrorCode, err)
	}

	connectionID, err := didComm.Connect(request.Auth, request.Invitation,
		wallet.WithConnectTimeout(request.Timeout), wallet.WithReuseDID(request.ReuseConnection),
		wallet.WithReuseAnyConnection(request.ReuseAnyConnection), wallet.WithMyLabel(request.MyLabel),
		wallet.WithRouterConnections(request.RouterConnections...))
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, ConnectMethod, err.Error())

		return command.NewExecuteError(DIDConnectErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ConnectResponse{ConnectionID: connectionID}, logger)

	logutil.LogDebug(logger, vcwallet.CommandName, ConnectMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID),
		logutil.CreateKeyValueString(invitationIDString, request.Invitation.ID),
		logutil.CreateKeyValueString(LabelString, request.MyLabel),
		logutil.CreateKeyValueString(connectionIDString, connectionID))

	return nil
}

// ProposePresentation accepts out-of-band invitation and sends message proposing presentation
// from wallet to relying party.
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#proposepresentation
//
// Currently Supporting
// [0454-present-proof-v2](https://github.com/hyperledger/aries-rfcs/tree/master/features/0454-present-proof-v2)
func (o *Command) ProposePresentation(rw io.Writer, req io.Reader) command.Error {
	request := &ProposePresentationRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, ProposePresentationMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, ProposePresentationMethod, err.Error())

		return command.NewExecuteError(ProposePresentationErrorCode, err)
	}

	didComm, err := wallet.NewDidComm(vcWallet, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, ProposePresentationMethod, err.Error())

		return command.NewExecuteError(ProposePresentationErrorCode, err)
	}

	msg, err := didComm.ProposePresentation(request.Auth, request.Invitation,
		wallet.WithFromDID(request.FromDID), wallet.WithInitiateTimeout(request.Timeout),
		wallet.WithConnectOptions(wallet.WithConnectTimeout(request.ConnectionOpts.Timeout),
			wallet.WithReuseDID(request.ConnectionOpts.ReuseConnection),
			wallet.WithReuseAnyConnection(request.ConnectionOpts.ReuseAnyConnection),
			wallet.WithMyLabel(request.ConnectionOpts.MyLabel),
			wallet.WithRouterConnections(request.ConnectionOpts.RouterConnections...)))
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, ProposePresentationMethod, err.Error())

		return command.NewExecuteError(ProposePresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ProposePresentationResponse{PresentationRequest: msg}, logger)

	logutil.LogDebug(logger, vcwallet.CommandName, ProposePresentationMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// PresentProof sends present proof message from wallet to relying party.
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#presentproof
//
// Currently Supporting
// [0454-present-proof-v2](https://github.com/hyperledger/aries-rfcs/tree/master/features/0454-present-proof-v2)
//
func (o *Command) PresentProof(rw io.Writer, req io.Reader) command.Error {
	request := &PresentProofRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, PresentProofMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, PresentProofMethod, err.Error())

		return command.NewExecuteError(PresentProofErrorCode, err)
	}

	didComm, err := wallet.NewDidComm(vcWallet, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, PresentProofMethod, err.Error())

		return command.NewExecuteError(PresentProofErrorCode, err)
	}

	status, err := didComm.PresentProof(request.Auth, request.ThreadID,
		prepareConcludeInteractionOpts(request.WaitForDone, request.Timeout, request.Presentation)...)
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, PresentProofMethod, err.Error())

		return command.NewExecuteError(PresentProofErrorCode, err)
	}

	command.WriteNillableResponse(rw, status, logger)

	logutil.LogDebug(logger, vcwallet.CommandName, PresentProofMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// ProposeCredential sends propose credential message from wallet to issuer.
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#proposecredential
//
// Currently Supporting : 0453-issueCredentialV2
// https://github.com/hyperledger/aries-rfcs/blob/main/features/0453-issue-credential-v2/README.md
//
func (o *Command) ProposeCredential(rw io.Writer, req io.Reader) command.Error {
	request := &ProposeCredentialRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, ProposeCredentialMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, ProposeCredentialMethod, err.Error())

		return command.NewExecuteError(ProposeCredentialErrorCode, err)
	}

	didComm, err := wallet.NewDidComm(vcWallet, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, ProposeCredentialMethod, err.Error())

		return command.NewExecuteError(ProposeCredentialErrorCode, err)
	}

	msg, err := didComm.ProposeCredential(request.Auth, request.Invitation,
		wallet.WithFromDID(request.FromDID), wallet.WithInitiateTimeout(request.Timeout),
		wallet.WithConnectOptions(wallet.WithConnectTimeout(request.ConnectionOpts.Timeout),
			wallet.WithReuseDID(request.ConnectionOpts.ReuseConnection),
			wallet.WithReuseAnyConnection(request.ConnectionOpts.ReuseAnyConnection),
			wallet.WithMyLabel(request.ConnectionOpts.MyLabel),
			wallet.WithRouterConnections(request.ConnectionOpts.RouterConnections...)))
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, ProposeCredentialMethod, err.Error())

		return command.NewExecuteError(ProposeCredentialErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ProposeCredentialResponse{OfferCredential: msg}, logger)

	logutil.LogDebug(logger, vcwallet.CommandName, ProposeCredentialMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// RequestCredential sends request credential message from wallet to issuer and
// optionally waits for credential response.
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#requestcredential
//
// Currently Supporting : 0453-issueCredentialV2
// https://github.com/hyperledger/aries-rfcs/blob/main/features/0453-issue-credential-v2/README.md
//
func (o *Command) RequestCredential(rw io.Writer, req io.Reader) command.Error {
	request := &RequestCredentialRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, RequestCredentialMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, RequestCredentialMethod, err.Error())

		return command.NewExecuteError(RequestCredentialErrorCode, err)
	}

	didComm, err := wallet.NewDidComm(vcWallet, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, RequestCredentialMethod, err.Error())

		return command.NewExecuteError(RequestCredentialErrorCode, err)
	}

	status, err := didComm.RequestCredential(request.Auth, request.ThreadID,
		prepareConcludeInteractionOpts(request.WaitForDone, request.Timeout, request.Presentation)...)
	if err != nil {
		logutil.LogInfo(logger, vcwallet.CommandName, RequestCredentialMethod, err.Error())

		return command.NewExecuteError(RequestCredentialErrorCode, err)
	}

	command.WriteNillableResponse(rw, status, logger)

	logutil.LogDebug(logger, vcwallet.CommandName, RequestCredentialMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

func prepareConcludeInteractionOpts(waitForDone bool, timeout time.Duration, presentation json.RawMessage) []wallet.ConcludeInteractionOptions { //nolint: lll
	var options []wallet.ConcludeInteractionOptions

	if waitForDone {
		options = append(options, wallet.WaitForDone(timeout))
	}

	return append(options, wallet.FromRawPresentation(presentation))
}
