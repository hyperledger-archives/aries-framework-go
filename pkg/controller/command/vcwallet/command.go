/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Avast Software. All Rights Reserved.

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

	// ResolveCredentialManifestErrorCode for errors while resolving credential manifest from wallet.
	ResolveCredentialManifestErrorCode

	// SignJWTErrorCode for errors while signing a JWT using wallet.
	SignJWTErrorCode

	// VerifyJWTErrorCode for errors while verifying a JWT using wallet.
	VerifyJWTErrorCode
)

// All command operations.
const (
	CommandName = "vcwallet"

	// command methods.
	CreateProfileMethod             = "CreateProfile"
	UpdateProfileMethod             = "UpdateProfile"
	ProfileExistsMethod             = "ProfileExists"
	OpenMethod                      = "Open"
	CloseMethod                     = "Close"
	AddMethod                       = "Add"
	RemoveMethod                    = "Remove"
	GetMethod                       = "Get"
	GetAllMethod                    = "GetAll"
	QueryMethod                     = "Query"
	SignJWTMethod                   = "SignJWT"
	VerifyJWTMethod                 = "VerifyJWT"
	IssueMethod                     = "Issue"
	ProveMethod                     = "Prove"
	VerifyMethod                    = "Verify"
	DeriveMethod                    = "Derive"
	CreateKeyPairMethod             = "CreateKeyPair"
	ResolveCredentialManifestMethod = "ResolveCredentialManifest"
)

// miscellaneous constants for the vc wallet command controller.
const (
	// log constants.
	logSuccess   = "success"
	logUserIDKey = "userID"

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

// GNAPHeaderSigner signs a request using GNAP, for resource server access authorization.
type GNAPHeaderSigner func(req *http.Request) (*http.Header, error)

// Config contains properties to customize verifiable credential wallet controller.
// All properties of this config are optional, but they can be used to customize wallet's webkms and edv client's.
type Config struct {
	// EDV header signer, typically used for introducing zcapld feature.
	EdvAuthzProvider AuthCapabilityProvider
	// Web KMS header signer, typically used for introducing zcapld feature.
	WebKMSAuthzProvider AuthCapabilityProvider
	// Web KMS header signer for GNAP authorization.
	WebKMSGNAPSigner GNAPHeaderSigner
	// EDV header signer for GNAP authorization.
	EDVGNAPSigner GNAPHeaderSigner
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
	// Indicate if a data model of json-ld content stored in the wallet should be validated.
	ValidateDataModel bool
}

// provider contains dependencies for the verifiable credential wallet command controller
// and is typically created by using aries.Context().
type provider interface {
	StorageProvider() storage.Provider
	VDRegistry() vdr.Registry
	Crypto() crypto.Crypto
	JSONLDDocumentLoader() ld.DocumentLoader
	MediaTypeProfiles() []string
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
		cmdutil.NewCommandHandler(CommandName, SignJWTMethod, o.SignJWT),
		cmdutil.NewCommandHandler(CommandName, VerifyJWTMethod, o.VerifyJWT),
		cmdutil.NewCommandHandler(CommandName, IssueMethod, o.Issue),
		cmdutil.NewCommandHandler(CommandName, ProveMethod, o.Prove),
		cmdutil.NewCommandHandler(CommandName, VerifyMethod, o.Verify),
		cmdutil.NewCommandHandler(CommandName, DeriveMethod, o.Derive),
		cmdutil.NewCommandHandler(CommandName, CreateKeyPairMethod, o.CreateKeyPair),
		cmdutil.NewCommandHandler(CommandName, ResolveCredentialManifestMethod, o.ResolveCredentialManifest),
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

	addOpts := []wallet.AddContentOptions{
		wallet.AddByCollection(request.CollectionID),
	}

	if o.config.ValidateDataModel {
		addOpts = append(addOpts, wallet.ValidateContent())
	}

	err = vcWallet.Add(request.Auth, request.ContentType, request.Content, addOpts...)
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

// SignJWT signs a JWT using a key in wallet.
func (o *Command) SignJWT(rw io.Writer, req io.Reader) command.Error {
	request := &SignJWTRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, SignJWTMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, SignJWTMethod, err.Error())

		return command.NewExecuteError(SignJWTErrorCode, err)
	}

	jwt, err := vcWallet.SignJWT(request.Auth, request.Headers, request.Claims, request.KID)
	if err != nil {
		logutil.LogInfo(logger, CommandName, SignJWTMethod, err.Error())

		return command.NewExecuteError(SignJWTErrorCode, err)
	}

	command.WriteNillableResponse(rw, &SignJWTResponse{JWT: jwt}, logger)

	logutil.LogDebug(logger, CommandName, SignJWTMethod, logSuccess,
		logutil.CreateKeyValueString(logUserIDKey, request.UserID))

	return nil
}

// VerifyJWT verifies a JWT using wallet.
func (o *Command) VerifyJWT(rw io.Writer, req io.Reader) command.Error {
	request := &VerifyJWTRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, VerifyJWTMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, VerifyJWTMethod, err.Error())

		return command.NewExecuteError(VerifyJWTErrorCode, err)
	}

	err = vcWallet.VerifyJWT(request.JWT)
	errString := ""

	if err != nil {
		errString = err.Error()
	}

	command.WriteNillableResponse(rw, &VerifyJWTResponse{Verified: err == nil, Error: errString}, logger)

	logutil.LogDebug(logger, CommandName, VerifyJWTMethod, logSuccess,
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

// ResolveCredentialManifest resolves given credential manifest by credential response or credential.
// Supports: https://identity.foundation/credential-manifest/
//
// Writes list of resolved descriptors to writer or returns error if operation fails.
func (o *Command) ResolveCredentialManifest(rw io.Writer, req io.Reader) command.Error {
	request := &ResolveCredentialManifestRequest{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, ResolveCredentialManifestMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, err)
	}

	vcWallet, err := wallet.New(request.UserID, o.ctx)
	if err != nil {
		logutil.LogInfo(logger, CommandName, ResolveCredentialManifestMethod, err.Error())

		return command.NewExecuteError(ResolveCredentialManifestErrorCode, err)
	}

	resolved, err := vcWallet.ResolveCredentialManifest(request.Auth, request.Manifest,
		prepareResolveManifestOption(request))
	if err != nil {
		logutil.LogInfo(logger, CommandName, ResolveCredentialManifestMethod, err.Error())

		return command.NewExecuteError(ResolveCredentialManifestErrorCode, err)
	}

	command.WriteNillableResponse(rw, &ResolveCredentialManifestResponse{Resolved: resolved}, logger)

	logutil.LogDebug(logger, CommandName, ResolveCredentialManifestMethod, logSuccess,
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
// nolint: lll
func prepareUnlockOptions(rqst *UnlockWalletRequest, conf *Config) ([]wallet.UnlockOptions, error) { // nolint:funlen,gocyclo
	var options []wallet.UnlockOptions

	if rqst.LocalKMSPassphrase != "" {
		options = append(options, wallet.WithUnlockByPassphrase(rqst.LocalKMSPassphrase))
	}

	var webkmsOpts []webkms.Opt

	if rqst.WebKMSAuth != nil {
		var webKMSHeader func(*http.Request) (*http.Header, error)

		switch {
		case rqst.WebKMSAuth.Capability != "": // zcap ld signing
			if conf.WebKMSAuthzProvider == nil {
				return nil, fmt.Errorf("authorization capability for WebKMS is not configured")
			}

			signer := conf.WebKMSAuthzProvider.GetHeaderSigner(rqst.WebKMSAuth.AuthZKeyStoreURL,
				rqst.WebKMSAuth.AuthToken, rqst.WebKMSAuth.SecretShare)

			webKMSHeader = func(req *http.Request) (*http.Header, error) {
				return signer.SignHeader(req, []byte(rqst.WebKMSAuth.Capability))
			}
		case rqst.WebKMSAuth.AuthToken != "": // auth token
			webKMSHeader = func(req *http.Request) (*http.Header, error) {
				req.Header.Set("authorization", fmt.Sprintf("Bearer %s", rqst.WebKMSAuth.AuthToken))

				return &req.Header, nil
			}
		case rqst.WebKMSAuth.GNAPToken != "": // GNAP token
			if conf.WebKMSGNAPSigner != nil {
				webKMSHeader = conf.WebKMSGNAPSigner
			} else {
				webKMSHeader = func(req *http.Request) (*http.Header, error) {
					req.Header.Set("authorization", fmt.Sprintf("GNAP %s", rqst.WebKMSAuth.GNAPToken))

					return &req.Header, nil
				}
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

		switch {
		case rqst.EDVUnlock.Capability != "": // zcap ld signing
			if conf.EdvAuthzProvider == nil {
				return nil, fmt.Errorf("authorization capability for EDV is not configured")
			}

			signer := conf.EdvAuthzProvider.GetHeaderSigner(rqst.EDVUnlock.AuthZKeyStoreURL,
				rqst.EDVUnlock.AuthToken, rqst.EDVUnlock.SecretShare)

			edvHeader = func(req *http.Request) (*http.Header, error) {
				return signer.SignHeader(req, []byte(rqst.EDVUnlock.Capability))
			}
		case rqst.EDVUnlock.AuthToken != "": // auth token
			edvHeader = func(req *http.Request) (*http.Header, error) {
				req.Header.Set("authorization", fmt.Sprintf("Bearer %s", rqst.EDVUnlock.AuthToken))

				return &req.Header, nil
			}
		case rqst.EDVUnlock.GNAPToken != "": // GNAP token
			if conf.EDVGNAPSigner != nil {
				edvHeader = conf.EDVGNAPSigner
			} else {
				edvHeader = func(req *http.Request) (*http.Header, error) {
					req.Header.Set("authorization", fmt.Sprintf("GNAP %s", rqst.EDVUnlock.GNAPToken))

					return &req.Header, nil
				}
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

func prepareResolveManifestOption(rqst *ResolveCredentialManifestRequest) wallet.ResolveManifestOption {
	if len(rqst.Response) > emptyRawLength {
		return wallet.ResolveRawResponse(rqst.Response)
	}

	if len(rqst.Credential) > emptyRawLength {
		return wallet.ResolveRawCredential(rqst.DescriptorID, rqst.Credential)
	}

	if rqst.CredentialID != "" {
		return wallet.ResolveCredentialID(rqst.DescriptorID, rqst.CredentialID)
	}

	return nil
}
