/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/component/storage/edv"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

var logger = log.New("aries-framework/command/vcwallet")

// Error codes.
const (
	// InvalidRequestErrorCode is typically a code for invalid requests.
	InvalidRequestErrorCode = command.Code(iota + command.VCWallet)

	// CreateProfileErrorCode for errors during create wallet profile operations.
	CreateProfileErrorCode

	// UpdateProfileErrorCode for errors during update wallet profile operations.
	UpdateProfileErrorCode

	// OpenWalletErrorCode for errors during wallet unlock operations.
	OpenWalletErrorCode

	// CloseWalletErrorCode for errors during wallet lock operations.
	CloseWalletErrorCode

	// AddToWalletErrorCode for errors while adding contents to wallet.
	AddToWalletErrorCode

	// RemoveFromWalletErrorCode for errors while removing contents from wallet.
	RemoveFromWalletErrorCode

	// GetFromWalletErrorCode for errors while getting a content from wallet.
	GetFromWalletErrorCode

	// GetAllFromWalletErrorCode for errors while getting all contents from wallet.
	GetAllFromWalletErrorCode

	// QueryWalletErrorCode for errors while querying credentials contents from wallet.
	QueryWalletErrorCode

	// IssueFromWalletErrorCode for errors while issuing a credential from wallet.
	IssueFromWalletErrorCode

	// ProveFromWalletErrorCode for errors while producing a presentation from wallet.
	ProveFromWalletErrorCode

	// VerifyFromWalletErrorCode for errors while verifying a presentation or credential from wallet.
	VerifyFromWalletErrorCode

	// DeriveFromWalletErrorCode for errors while deriving a credential from wallet.
	DeriveFromWalletErrorCode

	// CreateKeyPairFromWalletErrorCode for errors while creating key pair from wallet.
	CreateKeyPairFromWalletErrorCode

	// ProfileExistsErrorCode for errors while checking if profile exists for a wallet user.
	ProfileExistsErrorCode

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
	CommandName = "vcwallet"

	// command methods.
	CreateProfileMethod       = "CreateProfile"
	UpdateProfileMethod       = "UpdateProfile"
	ProfileExistsMethod       = "ProfileExists"
	OpenMethod                = "Open"
	CloseMethod               = "Close"
	AddMethod                 = "Add"
	RemoveMethod              = "Remove"
	GetMethod                 = "Get"
	GetAllMethod              = "GetAll"
	QueryMethod               = "Query"
	IssueMethod               = "Issue"
	ProveMethod               = "Prove"
	VerifyMethod              = "Verify"
	DeriveMethod              = "Derive"
	CreateKeyPairMethod       = "CreateKeyPair"
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

	emptyRawLength = 4

	defaultTokenExpiry = 5 * time.Minute
)

// AuthCapabilityProvider is for providing Authorization Capabilities (ZCAP-LD) feature for
// wallet's EDV and WebKMS components.
type AuthCapabilityProvider interface {
	// Returns HTTP Header Signer.
	GetHeaderSigner(authzKeyStoreURL, accessToken, secretShare string) HTTPHeaderSigner
}

// HTTPHeaderSigner is for http header signing, typically used for zcapld functionality.
type HTTPHeaderSigner interface {
	// SignHeader header with capability.
	SignHeader(req *http.Request, capabilityBytes []byte) (*http.Header, error)
}

// Config contains properties to customize verifiable credential wallet controller.
// All properties of this config are optional, but they can be used to customize wallet's webkms and edv client's.
type Config struct {
	// EDV header signer, typically used for introducing zcapld feature.
	EdvAuthzProvider AuthCapabilityProvider
	// Web KMS header signer, typically used for introducing zcapld feature.
	WebKMSAuthzProvider AuthCapabilityProvider
	// option is a performance optimization that speeds up queries by getting full documents from
	// the EDV server instead of only document locations.
	EDVReturnFullDocumentsOnQuery bool
	// this EDV option is a performance optimization that allows for restStore.Batch to only require one REST call.
	EDVBatchEndpointExtensionEnabled bool
	// Aries Web KMS cache size configuration.
	WebKMSCacheSize int
	// Default token expiry for all wallet profiles created.
	// Will be used only if wallet unlock request doesn't supply default timeout value.
	DefaultTokenExpiry time.Duration
}

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

// Command contains operations provided by verifiable credential wallet controller.
type Command struct {
	ctx    provider
	config *Config
}

// New returns new verifiable credential wallet controller command instance.
func New(p provider, config *Config) *Command {
	cmd := &Command{ctx: p, config: &Config{}}

	if config != nil {
		cmd.config = config
	}

	if cmd.config.DefaultTokenExpiry == 0 {
		cmd.config.DefaultTokenExpiry = defaultTokenExpiry
	}

	return cmd
}

// GetHandlers returns list of all commands supported by this controller command.
func (o *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, CreateProfileMethod, o.CreateProfile),
		cmdutil.NewCommandHandler(CommandName, UpdateProfileMethod, o.UpdateProfile),
		cmdutil.NewCommandHandler(CommandName, ProfileExistsMethod, o.ProfileExists),
		cmdutil.NewCommandHandler(CommandName, OpenMethod, o.Open),
		cmdutil.NewCommandHandler(CommandName, CloseMethod, o.Close),
		cmdutil.NewCommandHandler(CommandName, AddMethod, o.Add),
		cmdutil.NewCommandHandler(CommandName, RemoveMethod, o.Remove),
		cmdutil.NewCommandHandler(CommandName, GetMethod, o.Get),
		cmdutil.NewCommandHandler(CommandName, GetAllMethod, o.GetAll),
		cmdutil.NewCommandHandler(CommandName, QueryMethod, o.Query),
		cmdutil.NewCommandHandler(CommandName, IssueMethod, o.Issue),
		cmdutil.NewCommandHandler(CommandName, ProveMethod, o.Prove),
		cmdutil.NewCommandHandler(CommandName, VerifyMethod, o.Verify),
		cmdutil.NewCommandHandler(CommandName, DeriveMethod, o.Derive),
		cmdutil.NewCommandHandler(CommandName, CreateKeyPairMethod, o.CreateKeyPair),
		cmdutil.NewCommandHandler(CommandName, ConnectMethod, o.Connect),
		cmdutil.NewCommandHandler(CommandName, ProposePresentationMethod, o.ProposePresentation),
		cmdutil.NewCommandHandler(CommandName, PresentProofMethod, o.PresentProof),
		cmdutil.NewCommandHandler(CommandName, ProposeCredentialMethod, o.ProposeCredential),
		cmdutil.NewCommandHandler(CommandName, RequestCredentialMethod, o.RequestCredential),
	}
}

// CreateProfile creates new wallet profile for given user.
func (o *Command) CreateProfile(rw io.Writer, req io.Reader) command.Error {
	request := &CreateOrUpdateProfileRequest{}

	err := json.NewDecoder(req).Decode(request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CreateProfileMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	// create profile.
	err = wallet.CreateProfile(request.UserID, o.ctx, prepareProfileOptions(request)...)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CreateProfileMethod, err.Error())

		return command.NewExecuteError(CreateProfileErrorCode, err)
	}

	// create EDV keys if profile is using local kms.
	if request.LocalKMSPassphrase != "" && request.EDVConfiguration != nil {
		err = wallet.CreateDataVaultKeyPairs(request.UserID, o.ctx, wallet.WithUnlockByPassphrase(request.LocalKMSPassphrase))
		if err != nil {
			logutil.LogInfo(logger, CommandName, CreateProfileMethod, err.Error())

			return command.NewExecuteError(CreateProfileErrorCode, err)
		}
	}

	logutil.LogDebug(logger, CommandName, CreateProfileMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// UpdateProfile updates an existing wallet profile for given user.
func (o *Command) UpdateProfile(rw io.Writer, req io.Reader) command.Error {
	request := &CreateOrUpdateProfileRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, UpdateProfileMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	// update profile.
	err = wallet.UpdateProfile(request.UserID, o.ctx, prepareProfileOptions(request)...)
	if err != nil {
		logutil.LogInfo(logger, CommandName, UpdateProfileMethod, err.Error())

		return command.NewExecuteError(UpdateProfileErrorCode, err)
	}

	logutil.LogDebug(logger, CommandName, UpdateProfileMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// ProfileExists checks if wallet profile exists for given wallet user.
func (o *Command) ProfileExists(rw io.Writer, req io.Reader) command.Error {
	user := &WalletUser{}

	err := json.NewDecoder(req).Decode(&user)
	if err != nil {
		logutil.LogInfo(logger, CommandName, ProfileExistsMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	err = wallet.ProfileExists(user.ID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, ProfileExistsMethod, err.Error())

		return command.NewExecuteError(ProfileExistsErrorCode, err)
	}

	logutil.LogDebug(logger, CommandName, ProfileExistsMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, user.ID))

	return nil
}

// Open unlocks given user's wallet and returns a token for subsequent use of wallet features.
func (o *Command) Open(rw io.Writer, req io.Reader) command.Error {
	request := &UnlockWalletRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, OpenMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	opts, err := prepareUnlockOptions(request, o.config)
	if err != nil {
		logutil.LogInfo(logger, CommandName, OpenMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, OpenMethod, err.Error())

		return command.NewExecuteError(OpenWalletErrorCode, err)
	}

	token, err := vcWallet.Open(opts...)
	if err != nil {
		logutil.LogInfo(logger, CommandName, OpenMethod, err.Error())

		return command.NewExecuteError(OpenWalletErrorCode, err)
	}

	command.WriteNillableResponse(rw, UnlockWalletResponse{Token: token}, logger)

	logutil.LogDebug(logger, CommandName, OpenMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// Close locks given user's wallet.
func (o *Command) Close(rw io.Writer, req io.Reader) command.Error {
	request := &LockWalletRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CloseMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CloseMethod, err.Error())

		return command.NewExecuteError(CloseWalletErrorCode, err)
	}

	closed := vcWallet.Close()

	command.WriteNillableResponse(rw, LockWalletResponse{Closed: closed}, logger)

	logutil.LogDebug(logger, CommandName, CloseMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// Add adds given data model to wallet content store.
func (o *Command) Add(rw io.Writer, req io.Reader) command.Error {
	request := &AddContentRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, AddMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, AddMethod, err.Error())

		return command.NewExecuteError(AddToWalletErrorCode, err)
	}

	err = vcWallet.Add(request.Auth, request.ContentType, request.Content, wallet.AddByCollection(request.CollectionID))
	if err != nil {
		logutil.LogInfo(logger, CommandName, AddMethod, err.Error())

		return command.NewExecuteError(AddToWalletErrorCode, err)
	}

	logutil.LogDebug(logger, CommandName, AddMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// Remove deletes given content from wallet content store.
func (o *Command) Remove(rw io.Writer, req io.Reader) command.Error {
	request := &RemoveContentRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, RemoveMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, RemoveMethod, err.Error())

		return command.NewExecuteError(RemoveFromWalletErrorCode, err)
	}

	err = vcWallet.Remove(request.Auth, request.ContentType, request.ContentID)
	if err != nil {
		logutil.LogInfo(logger, CommandName, RemoveMethod, err.Error())

		return command.NewExecuteError(RemoveFromWalletErrorCode, err)
	}

	logutil.LogDebug(logger, CommandName, RemoveMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// Get returns wallet content by ID from wallet content store.
func (o *Command) Get(rw io.Writer, req io.Reader) command.Error {
	request := &GetContentRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, GetMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, GetMethod, err.Error())

		return command.NewExecuteError(GetFromWalletErrorCode, err)
	}

	content, err := vcWallet.Get(request.Auth, request.ContentType, request.ContentID)
	if err != nil {
		logutil.LogInfo(logger, CommandName, GetMethod, err.Error())

		return command.NewExecuteError(GetFromWalletErrorCode, err)
	}

	command.WriteNillableResponse(rw, GetContentResponse{Content: content}, logger)

	logutil.LogDebug(logger, CommandName, GetMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// GetAll gets all wallet content from wallet content store for given type.
func (o *Command) GetAll(rw io.Writer, req io.Reader) command.Error {
	request := &GetAllContentRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, GetAllMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, GetAllMethod, err.Error())

		return command.NewExecuteError(GetAllFromWalletErrorCode, err)
	}

	contents, err := vcWallet.GetAll(request.Auth, request.ContentType,
		wallet.FilterByCollection(request.CollectionID))
	if err != nil {
		logutil.LogInfo(logger, CommandName, GetAllMethod, err.Error())

		return command.NewExecuteError(GetAllFromWalletErrorCode, err)
	}

	command.WriteNillableResponse(rw, GetAllContentResponse{Contents: contents}, logger)

	logutil.LogDebug(logger, CommandName, GetAllMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// Query runs credential queries against wallet credential contents and
// returns presentation containing credential results.
func (o *Command) Query(rw io.Writer, req io.Reader) command.Error {
	request := &ContentQueryRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, GetAllMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, GetAllMethod, err.Error())

		return command.NewExecuteError(QueryWalletErrorCode, err)
	}

	presentations, err := vcWallet.Query(request.Auth, request.Query...)
	if err != nil {
		logutil.LogInfo(logger, CommandName, GetAllMethod, err.Error())

		return command.NewExecuteError(QueryWalletErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ContentQueryResponse{Results: presentations}, logger)

	logutil.LogDebug(logger, CommandName, GetAllMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// Issue adds proof to a Verifiable Credential from wallet.
func (o *Command) Issue(rw io.Writer, req io.Reader) command.Error {
	request := &IssueRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, IssueMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, IssueMethod, err.Error())

		return command.NewExecuteError(IssueFromWalletErrorCode, err)
	}

	credential, err := vcWallet.Issue(request.Auth, request.Credential, request.ProofOptions)
	if err != nil {
		logutil.LogInfo(logger, CommandName, IssueMethod, err.Error())

		return command.NewExecuteError(IssueFromWalletErrorCode, err)
	}

	command.WriteNillableResponse(rw, &IssueResponse{Credential: credential}, logger)

	logutil.LogDebug(logger, CommandName, IssueMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// Prove produces a Verifiable Presentation from wallet.
func (o *Command) Prove(rw io.Writer, req io.Reader) command.Error {
	request := &ProveRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, ProveMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, ProveMethod, err.Error())

		return command.NewExecuteError(ProveFromWalletErrorCode, err)
	}

	vp, err := vcWallet.Prove(request.Auth, request.ProofOptions, prepareProveOptions(request)...)
	if err != nil {
		logutil.LogInfo(logger, CommandName, ProveMethod, err.Error())

		return command.NewExecuteError(ProveFromWalletErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ProveResponse{Presentation: vp}, logger)

	logutil.LogDebug(logger, CommandName, ProveMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// Verify verifies credential/presentation from wallet.
func (o *Command) Verify(rw io.Writer, req io.Reader) command.Error {
	request := &VerifyRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, VerifyMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, VerifyMethod, err.Error())

		return command.NewExecuteError(VerifyFromWalletErrorCode, err)
	}

	option, err := prepareVerifyOption(request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, VerifyMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	verified, err := vcWallet.Verify(request.Auth, option)

	response := &VerifyResponse{Verified: verified}

	if err != nil {
		response.Error = err.Error()
	}

	command.WriteNillableResponse(rw, response, logger)

	logutil.LogDebug(logger, CommandName, VerifyMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// Derive derives a credential from wallet.
func (o *Command) Derive(rw io.Writer, req io.Reader) command.Error {
	request := &DeriveRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, DeriveMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, DeriveMethod, err.Error())

		return command.NewExecuteError(DeriveFromWalletErrorCode, err)
	}

	derived, err := vcWallet.Derive(request.Auth, prepareDeriveOption(request), request.DeriveOptions)
	if err != nil {
		logutil.LogInfo(logger, CommandName, DeriveMethod, err.Error())

		return command.NewExecuteError(DeriveFromWalletErrorCode, err)
	}

	command.WriteNillableResponse(rw, &DeriveResponse{Credential: derived}, logger)

	logutil.LogDebug(logger, CommandName, DeriveMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// CreateKeyPair creates key pair from wallet.
func (o *Command) CreateKeyPair(rw io.Writer, req io.Reader) command.Error {
	request := &CreateKeyPairRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CreateKeyPairMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CreateKeyPairMethod, err.Error())

		return command.NewExecuteError(CreateKeyPairFromWalletErrorCode, err)
	}

	response, err := vcWallet.CreateKeyPair(request.Auth, request.KeyType)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CreateKeyPairMethod, err.Error())

		return command.NewExecuteError(CreateKeyPairFromWalletErrorCode, err)
	}

	command.WriteNillableResponse(rw, &CreateKeyPairResponse{response}, logger)

	logutil.LogDebug(logger, CommandName, CreateKeyPairMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// Connect accepts out-of-band invitations and performs DID exchange.
func (o *Command) Connect(rw io.Writer, req io.Reader) command.Error {
	request := &ConnectRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, ConnectMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, ConnectMethod, err.Error())

		return command.NewExecuteError(DIDConnectErrorCode, err)
	}

	connectionID, err := vcWallet.Connect(request.Auth, request.Invitation,
		wallet.WithConnectTimeout(request.Timeout), wallet.WithReuseDID(request.ReuseConnection),
		wallet.WithReuseAnyConnection(request.ReuseAnyConnection), wallet.WithMyLabel(request.MyLabel),
		wallet.WithRouterConnections(request.RouterConnections...))
	if err != nil {
		logutil.LogInfo(logger, CommandName, ConnectMethod, err.Error())

		return command.NewExecuteError(DIDConnectErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ConnectResponse{ConnectionID: connectionID}, logger)

	logutil.LogDebug(logger, CommandName, ConnectMethod, logSuccess,
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
		logutil.LogInfo(logger, CommandName, ProposePresentationMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, ProposePresentationMethod, err.Error())

		return command.NewExecuteError(ProposePresentationErrorCode, err)
	}

	msg, err := vcWallet.ProposePresentation(request.Auth, request.Invitation,
		wallet.WithFromDID(request.FromDID), wallet.WithInitiateTimeout(request.Timeout),
		wallet.WithConnectOptions(wallet.WithConnectTimeout(request.ConnectionOpts.Timeout),
			wallet.WithReuseDID(request.ConnectionOpts.ReuseConnection),
			wallet.WithReuseAnyConnection(request.ConnectionOpts.ReuseAnyConnection),
			wallet.WithMyLabel(request.ConnectionOpts.MyLabel),
			wallet.WithRouterConnections(request.ConnectionOpts.RouterConnections...)))
	if err != nil {
		logutil.LogInfo(logger, CommandName, ProposePresentationMethod, err.Error())

		return command.NewExecuteError(ProposePresentationErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ProposePresentationResponse{PresentationRequest: msg}, logger)

	logutil.LogDebug(logger, CommandName, ProposePresentationMethod, logSuccess,
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
		logutil.LogInfo(logger, CommandName, PresentProofMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, PresentProofMethod, err.Error())

		return command.NewExecuteError(PresentProofErrorCode, err)
	}

	status, err := vcWallet.PresentProof(request.Auth, request.ThreadID,
		prepareConcludeInteractionOpts(request.WaitForDone, request.Timeout, request.Presentation)...)
	if err != nil {
		logutil.LogInfo(logger, CommandName, PresentProofMethod, err.Error())

		return command.NewExecuteError(PresentProofErrorCode, err)
	}

	command.WriteNillableResponse(rw, status, logger)

	logutil.LogDebug(logger, CommandName, PresentProofMethod, logSuccess,
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
		logutil.LogInfo(logger, CommandName, ProposeCredentialMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, ProposeCredentialMethod, err.Error())

		return command.NewExecuteError(ProposeCredentialErrorCode, err)
	}

	msg, err := vcWallet.ProposeCredential(request.Auth, request.Invitation,
		wallet.WithFromDID(request.FromDID), wallet.WithInitiateTimeout(request.Timeout),
		wallet.WithConnectOptions(wallet.WithConnectTimeout(request.ConnectionOpts.Timeout),
			wallet.WithReuseDID(request.ConnectionOpts.ReuseConnection),
			wallet.WithReuseAnyConnection(request.ConnectionOpts.ReuseAnyConnection),
			wallet.WithMyLabel(request.ConnectionOpts.MyLabel),
			wallet.WithRouterConnections(request.ConnectionOpts.RouterConnections...)))
	if err != nil {
		logutil.LogInfo(logger, CommandName, ProposeCredentialMethod, err.Error())

		return command.NewExecuteError(ProposeCredentialErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ProposeCredentialResponse{OfferCredential: msg}, logger)

	logutil.LogDebug(logger, CommandName, ProposeCredentialMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// RequestCredential sends request credential message from wallet to issuer and
// optionally waits for credential fulfillment.
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#requestcredential
//
// Currently Supporting : 0453-issueCredentialV2
// https://github.com/hyperledger/aries-rfcs/blob/main/features/0453-issue-credential-v2/README.md
//
func (o *Command) RequestCredential(rw io.Writer, req io.Reader) command.Error {
	request := &RequestCredentialRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, RequestCredentialMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, RequestCredentialMethod, err.Error())

		return command.NewExecuteError(RequestCredentialErrorCode, err)
	}

	status, err := vcWallet.RequestCredential(request.Auth, request.ThreadID,
		prepareConcludeInteractionOpts(request.WaitForDone, request.Timeout, request.Presentation)...)
	if err != nil {
		logutil.LogInfo(logger, CommandName, RequestCredentialMethod, err.Error())

		return command.NewExecuteError(RequestCredentialErrorCode, err)
	}

	command.WriteNillableResponse(rw, status, logger)

	logutil.LogDebug(logger, CommandName, RequestCredentialMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// prepareProfileOptions prepares options for creating wallet profile.
func prepareProfileOptions(rqst *CreateOrUpdateProfileRequest) []wallet.ProfileOptions {
	var options []wallet.ProfileOptions

	if rqst.LocalKMSPassphrase != "" {
		options = append(options, wallet.WithPassphrase(rqst.LocalKMSPassphrase))
	}

	if rqst.KeyStoreURL != "" {
		options = append(options, wallet.WithKeyServerURL(rqst.KeyStoreURL))
	}

	if rqst.EDVConfiguration != nil {
		options = append(options, wallet.WithEDVStorage(
			rqst.EDVConfiguration.ServerURL, rqst.EDVConfiguration.VaultID,
			rqst.EDVConfiguration.EncryptionKeyID, rqst.EDVConfiguration.MACKeyID,
		))
	}

	return options
}

// prepareUnlockOptions prepares options for unlocking wallet.
//nolint: lll
func prepareUnlockOptions(rqst *UnlockWalletRequest, conf *Config) ([]wallet.UnlockOptions, error) { // nolint:funlen,gocyclo
	var options []wallet.UnlockOptions

	if rqst.LocalKMSPassphrase != "" {
		options = append(options, wallet.WithUnlockByPassphrase(rqst.LocalKMSPassphrase))
	}

	var webkmsOpts []webkms.Opt

	if rqst.WebKMSAuth != nil {
		var webKMSHeader func(*http.Request) (*http.Header, error)

		if rqst.WebKMSAuth.Capability != "" { // zcap ld signing
			if conf.WebKMSAuthzProvider == nil {
				return nil, fmt.Errorf("authorization capability for WebKMS is not configured")
			}

			signer := conf.WebKMSAuthzProvider.GetHeaderSigner(rqst.WebKMSAuth.AuthZKeyStoreURL,
				rqst.WebKMSAuth.AuthToken, rqst.WebKMSAuth.SecretShare)

			webKMSHeader = func(req *http.Request) (*http.Header, error) {
				return signer.SignHeader(req, []byte(rqst.WebKMSAuth.Capability))
			}
		} else if rqst.WebKMSAuth.AuthToken != "" { // auth token
			webKMSHeader = func(req *http.Request) (*http.Header, error) {
				req.Header.Set("authorization", fmt.Sprintf("Bearer %s", rqst.EDVUnlock.AuthToken))

				return &req.Header, nil
			}
		}

		webkmsOpts = append(webkmsOpts, webkms.WithHeaders(webKMSHeader))
	}

	if conf.WebKMSCacheSize > 0 {
		webkmsOpts = append(webkmsOpts, webkms.WithCache(conf.WebKMSCacheSize))
	}

	var edvOpts []edv.RESTProviderOption

	if rqst.EDVUnlock != nil {
		var edvHeader func(*http.Request) (*http.Header, error)

		if rqst.EDVUnlock.Capability != "" { // zcap ld signing
			if conf.EdvAuthzProvider == nil {
				return nil, fmt.Errorf("authorization capability for EDV is not configured")
			}

			signer := conf.EdvAuthzProvider.GetHeaderSigner(rqst.EDVUnlock.AuthZKeyStoreURL,
				rqst.EDVUnlock.AuthToken, rqst.EDVUnlock.SecretShare)

			edvHeader = func(req *http.Request) (*http.Header, error) {
				return signer.SignHeader(req, []byte(rqst.EDVUnlock.Capability))
			}
		} else if rqst.EDVUnlock.AuthToken != "" { // auth token
			edvHeader = func(req *http.Request) (*http.Header, error) {
				req.Header.Set("authorization", fmt.Sprintf("Bearer %s", rqst.EDVUnlock.AuthToken))

				return &req.Header, nil
			}
		}

		edvOpts = append(edvOpts, edv.WithHeaders(edvHeader))
	}

	if conf.EDVBatchEndpointExtensionEnabled {
		edvOpts = append(edvOpts, edv.WithBatchEndpointExtension())
	}

	if conf.EDVReturnFullDocumentsOnQuery {
		edvOpts = append(edvOpts, edv.WithFullDocumentsReturnedFromQueries())
	}

	tokenExpiry := conf.DefaultTokenExpiry
	if rqst.Expiry > 0 {
		tokenExpiry = rqst.Expiry
	}

	options = append(options, wallet.WithUnlockWebKMSOptions(webkmsOpts...), wallet.WithUnlockEDVOptions(edvOpts...),
		wallet.WithUnlockExpiry(tokenExpiry))

	return options, nil
}

func prepareProveOptions(rqst *ProveRequest) []wallet.ProveOptions {
	var options []wallet.ProveOptions

	if len(rqst.StoredCredentials) > 0 {
		options = append(options, wallet.WithStoredCredentialsToProve(rqst.StoredCredentials...))
	}

	if len(rqst.RawCredentials) > 0 {
		options = append(options, wallet.WithRawCredentialsToProve(rqst.RawCredentials...))
	}

	if len(rqst.Presentation) > emptyRawLength {
		options = append(options, wallet.WithRawPresentationToProve(rqst.Presentation))
	}

	return options
}

func prepareVerifyOption(rqst *VerifyRequest) (wallet.VerificationOption, error) {
	if len(rqst.StoredCredentialID) > 0 {
		return wallet.WithStoredCredentialToVerify(rqst.StoredCredentialID), nil
	}

	if len(rqst.RawCredential) > emptyRawLength {
		return wallet.WithRawCredentialToVerify(rqst.RawCredential), nil
	}

	if len(rqst.Presentation) > emptyRawLength {
		return wallet.WithRawPresentationToVerify(rqst.Presentation), nil
	}

	return nil, errors.New("invalid option")
}

func prepareDeriveOption(rqst *DeriveRequest) wallet.CredentialToDerive {
	if len(rqst.StoredCredentialID) > 0 {
		return wallet.FromStoredCredential(rqst.StoredCredentialID)
	}

	return wallet.FromRawCredential(rqst.RawCredential)
}

func prepareConcludeInteractionOpts(waitForDone bool, timeout time.Duration, presentation json.RawMessage) []wallet.ConcludeInteractionOptions { //nolint: lll
	var options []wallet.ConcludeInteractionOptions

	if waitForDone {
		options = append(options, wallet.WaitForDone(timeout))
	}

	return append(options, wallet.FromRawPresentation(presentation))
}
