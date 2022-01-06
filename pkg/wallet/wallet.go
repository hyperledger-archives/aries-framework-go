/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/client/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/client/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
	"github.com/hyperledger/aries-framework-go/pkg/client/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/client/presentproof"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	didexchangeSvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	issuecredentialsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// Proof types.
const (
	// Ed25519Signature2018 ed25519 signature suite.
	Ed25519Signature2018 = "Ed25519Signature2018"
	// JSONWebSignature2020 json web signature suite.
	JSONWebSignature2020 = "JsonWebSignature2020"
	// BbsBlsSignature2020 BBS signature suite.
	BbsBlsSignature2020 = "BbsBlsSignature2020"
)

// miscellaneous constants.
const (
	bbsContext         = "https://w3id.org/security/bbs/v1"
	emptyRawLength     = 4
	msgEventBufferSize = 10
	ldJSONMimeType     = "application/ld+json"

	// protocol states.
	stateNameAbandoned  = "abandoned"
	stateNameAbandoning = "abandoning"
	stateNameDone       = "done"

	// web redirect constants.
	webRedirectStatusKey = "status"
	webRedirectURLKey    = "url"

	// timeout constants.
	defaultDIDExchangeTimeOut                = 120 * time.Second
	defaultWaitForRequestPresentationTimeOut = 120 * time.Second
	defaultWaitForPresentProofDone           = 120 * time.Second
	retryDelay                               = 500 * time.Millisecond
)

// proof options.
// nolint:gochecknoglobals
var (
	defaultSignatureRepresentation = verifiable.SignatureJWS
	supportedRelationships         = map[did.VerificationRelationship]string{
		did.Authentication:  "authentication",
		did.AssertionMethod: "assertionMethod",
	}
)

var logger = log.New("aries-framework/wallet")

// provider contains dependencies for the verifiable credential wallet
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

type provable interface {
	AddLinkedDataProof(context *verifiable.LinkedDataProofContext, jsonldOpts ...jsonld.ProcessorOpts) error
}

// Wallet enables access to verifiable credential wallet features.
type Wallet struct {
	// ID of wallet content owner
	userID string

	// wallet profile
	profile *profile

	// wallet content store
	contents *contentStore

	// crypto for wallet
	walletCrypto crypto.Crypto

	// storage provider
	storeProvider storage.Provider

	// wallet VDR
	vdr vdr.Registry

	// document loader for JSON-LD contexts
	jsonldDocumentLoader ld.DocumentLoader

	// present proof client
	presentProofClient *presentproof.Client

	// issue credential client
	issueCredentialClient *issuecredential.Client

	// out of band client
	oobClient *outofband.Client

	// out of band v2 client
	oobV2Client *outofbandv2.Client

	// did-exchange client
	didexchangeClient *didexchange.Client

	// connection lookup
	connectionLookup *connection.Lookup
}

// New returns new verifiable credential wallet for given user.
// returns error if wallet profile is not found.
// To create a new wallet profile, use `CreateProfile()`.
// To update an existing profile, use `UpdateProfile()`.
func New(userID string, ctx provider) (*Wallet, error) {
	store, err := newProfileStore(ctx.StorageProvider())
	if err != nil {
		return nil, fmt.Errorf("failed to get store to fetch VC wallet profile info: %w", err)
	}

	profile, err := store.get(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get VC wallet profile: %w", err)
	}

	presentProofClient, err := presentproof.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize present proof client: %w", err)
	}

	issueCredentialClient, err := issuecredential.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize issue credential client: %w", err)
	}

	oobClient, err := outofband.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize out-of-band client: %w", err)
	}

	oobV2Client, err := outofbandv2.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize out-of-band v2 client: %w", err)
	}

	connectionLookup, err := connection.NewLookup(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize connection lookup: %w", err)
	}

	didexchangeClient, err := didexchange.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize didexchange client: %w", err)
	}

	return &Wallet{
		userID:                userID,
		profile:               profile,
		storeProvider:         ctx.StorageProvider(),
		walletCrypto:          ctx.Crypto(),
		contents:              newContentStore(ctx.StorageProvider(), profile),
		vdr:                   ctx.VDRegistry(),
		jsonldDocumentLoader:  ctx.JSONLDDocumentLoader(),
		presentProofClient:    presentProofClient,
		issueCredentialClient: issueCredentialClient,
		oobClient:             oobClient,
		oobV2Client:           oobV2Client,
		didexchangeClient:     didexchangeClient,
		connectionLookup:      connectionLookup,
	}, nil
}

// CreateProfile creates a new verifiable credential wallet profile for given user.
// returns error if wallet profile is already created.
// Use `UpdateProfile()` for replacing an already created verifiable credential wallet profile.
func CreateProfile(userID string, ctx provider, options ...ProfileOptions) error {
	return createOrUpdate(userID, ctx, false, options...)
}

// UpdateProfile updates existing verifiable credential wallet profile.
// Caution:
// - you might lose your existing keys if you change kms options.
// - you might lose your existing wallet contents if you change storage/EDV options
// (ex: switching context storage provider or changing EDV settings).
func UpdateProfile(userID string, ctx provider, options ...ProfileOptions) error {
	return createOrUpdate(userID, ctx, true, options...)
}

// CreateDataVaultKeyPairs can be used create EDV key pairs for given profile.
// Wallet will create key pairs in profile kms and updates profile with newly generate EDV encryption & MAC key IDs.
func CreateDataVaultKeyPairs(userID string, ctx provider, options ...UnlockOptions) error {
	store, err := newProfileStore(ctx.StorageProvider())
	if err != nil {
		return fmt.Errorf("failed to get wallet user profile: failed to get store: %w", err)
	}

	profile, err := store.get(userID)
	if err != nil {
		return fmt.Errorf("failed to get wallet user profile: %w", err)
	}

	if profile.EDVConf == nil {
		return fmt.Errorf("invalid operation, no edv configuration found in profile: %w", err)
	}

	opts := &unlockOpts{}

	for _, opt := range options {
		opt(opts)
	}

	// unlock key manager
	token, err := keyManager().createKeyManager(profile, ctx.StorageProvider(), opts)
	if err != nil {
		return fmt.Errorf("failed to get key manager: %w", err)
	}

	defer keyManager().removeKeyManager(userID)

	// update profile
	err = updateProfile(token, profile)
	if err != nil {
		return fmt.Errorf("failed to create key pairs: %w", err)
	}

	// update profile
	err = store.save(profile, true)
	if err != nil {
		return fmt.Errorf("failed to update profile: %w", err)
	}

	return nil
}

func createOrUpdate(userID string, ctx provider, update bool, options ...ProfileOptions) error {
	opts := &profileOpts{}

	for _, opt := range options {
		opt(opts)
	}

	store, err := newProfileStore(ctx.StorageProvider())
	if err != nil {
		return fmt.Errorf("failed to get store to save VC wallet profile: %w", err)
	}

	var profile *profile

	// nolint: nestif
	if update {
		// find existing profile and update it.
		profile, err = store.get(userID)
		if err != nil {
			return fmt.Errorf("failed to update wallet user profile: %w", err)
		}

		err = profile.setKMSOptions(opts.passphrase, opts.secretLockSvc, opts.keyServerURL)
		if err != nil {
			return fmt.Errorf("failed to update wallet user profile KMS options: %w", err)
		}

		err = profile.setEDVOptions(opts.edvConf)
		if err != nil {
			return fmt.Errorf("failed to update EDV configuration")
		}
	} else {
		// create new profile.
		profile, err = createProfile(userID, opts)
		if err != nil {
			return fmt.Errorf("failed to create new  wallet user profile: %w", err)
		}
	}

	err = store.save(profile, update)
	if err != nil {
		return fmt.Errorf("failed to save VC wallet profile: %w", err)
	}

	return nil
}

// ProfileExists checks if profile exists for given wallet user, returns error if not found.
func ProfileExists(userID string, ctx provider) error {
	store, err := newProfileStore(ctx.StorageProvider())
	if err != nil {
		return fmt.Errorf("failed to get store to get VC wallet profile: %w", err)
	}

	_, err = store.get(userID)

	return err
}

// Open unlocks wallet's key manager instance & open wallet content store and
// returns a token for subsequent use of wallet features.
//
//	Args:
//		- unlock options for opening wallet.
//
//	Returns token with expiry that can be used for subsequent use of wallet features.
func (c *Wallet) Open(options ...UnlockOptions) (string, error) {
	opts := &unlockOpts{}

	for _, opt := range options {
		opt(opts)
	}

	// unlock key manager
	token, err := keyManager().createKeyManager(c.profile, c.storeProvider, opts)
	if err != nil {
		return "", err
	}

	// open content store using token
	err = c.contents.Open(token, opts)
	if err != nil {
		// close wallet if it fails to open store
		c.Close()

		return "", err
	}

	return token, nil
}

// Close expires token issued to this VC wallet, removes the key manager instance and closes wallet content store.
// returns false if token is not found or already expired for this wallet user.
func (c *Wallet) Close() bool {
	return keyManager().removeKeyManager(c.userID) && c.contents.Close()
}

// Export produces a serialized exported wallet representation.
// Only ciphertext wallet contents can be exported.
//
//	Args:
//		- auth: token to be used to lock the wallet before exporting.
//
//	Returns exported locked wallet.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//
func (c *Wallet) Export(auth string) (json.RawMessage, error) {
	// TODO to be added #2433
	return nil, fmt.Errorf("to be implemented")
}

// Import Takes a serialized exported wallet representation as input
// and imports all contents into wallet.
//
//	Args:
//		- contents: wallet content to be imported.
//		- auth: token used while exporting the wallet.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Key
//
func (c *Wallet) Import(auth string, contents json.RawMessage) error {
	// TODO to be added #2433
	return fmt.Errorf("to be implemented")
}

// Add adds given data model to wallet contents store.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Key
//
func (c *Wallet) Add(authToken string, contentType ContentType, content json.RawMessage, options ...AddContentOptions) error { //nolint: lll
	return c.contents.Save(authToken, contentType, content, options...)
}

// Remove removes wallet content by content ID.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//
func (c *Wallet) Remove(authToken string, contentType ContentType, contentID string) error {
	return c.contents.Remove(authToken, contentID, contentType)
}

// Get fetches a wallet content by content ID.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//
func (c *Wallet) Get(authToken string, contentType ContentType, contentID string) (json.RawMessage, error) {
	return c.contents.Get(authToken, contentID, contentType)
}

// GetAll fetches all wallet contents of given type.
// Returns map of key value from content store for given content type.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//
func (c *Wallet) GetAll(authToken string, contentType ContentType, options ...GetAllContentsOptions) (map[string]json.RawMessage, error) { //nolint: lll
	opts := &getAllContentsOpts{}

	for _, option := range options {
		option(opts)
	}

	if opts.collectionID != "" {
		return c.contents.GetAllByCollection(authToken, opts.collectionID, contentType)
	}

	return c.contents.GetAll(authToken, contentType)
}

// Query runs query against wallet credential contents and returns presentation containing credential results.
//
// This function may return multiple presentations as query result based on combination of query types used.
//
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#query
//
// Supported Query Types:
// 	- https://www.w3.org/TR/json-ld11-framing
// 	- https://identity.foundation/presentation-exchange
// 	- https://w3c-ccg.github.io/vp-request-spec/#query-by-example
// 	- https://w3c-ccg.github.io/vp-request-spec/#did-authentication-request
//
func (c *Wallet) Query(authToken string, params ...*QueryParams) ([]*verifiable.Presentation, error) {
	vcContents, err := c.contents.GetAll(authToken, Credential)
	if err != nil {
		return nil, fmt.Errorf("failed to query credentials: %w", err)
	}

	query := NewQuery(verifiable.NewVDRKeyResolver(newContentBasedVDR(authToken, c.vdr, c.contents)).PublicKeyFetcher(),
		c.jsonldDocumentLoader, params...)

	return query.PerformQuery(vcContents)
}

// Issue adds proof to a Verifiable Credential.
//
//	Args:
//		- auth token for unlocking kms.
//		- A verifiable credential with or without proof.
//		- Proof options.
//
func (c *Wallet) Issue(authToken string, credential json.RawMessage,
	options *ProofOptions) (*verifiable.Credential, error) {
	vc, err := verifiable.ParseCredential(credential, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(c.jsonldDocumentLoader))
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	purpose := did.AssertionMethod

	err = c.validateProofOption(authToken, options, purpose)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare proof: %w", err)
	}

	err = c.addLinkedDataProof(authToken, vc, options, purpose)
	if err != nil {
		return nil, fmt.Errorf("failed to issue credential: %w", err)
	}

	return vc, nil
}

// Prove produces a Verifiable Presentation.
//
//	Args:
// 		- auth token for unlocking kms.
//		- list of interfaces (string of credential IDs which can be resolvable to stored credentials in wallet or
//		raw credential or a presentation).
//		- proof options
//
func (c *Wallet) Prove(authToken string, proofOptions *ProofOptions, credentials ...ProveOptions) (*verifiable.Presentation, error) { //nolint: lll
	presentation, err := c.resolveOptionsToPresent(authToken, credentials...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve credentials from request: %w", err)
	}

	purpose := did.Authentication

	err = c.validateProofOption(authToken, proofOptions, purpose)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare proof: %w", err)
	}

	presentation.Holder = proofOptions.Controller

	err = c.addLinkedDataProof(authToken, presentation, proofOptions, purpose)
	if err != nil {
		return nil, fmt.Errorf("failed to prove credentials: %w", err)
	}

	return presentation, nil
}

// Verify takes Takes a Verifiable Credential or Verifiable Presentation as input,.
//
//	Args:
//		- verification option for sending different models (stored credential ID, raw credential, raw presentation).
//
// Returns: a boolean verified, and an error if verified is false.
func (c *Wallet) Verify(authToken string, options VerificationOption) (bool, error) {
	requestOpts := &verifyOpts{}

	options(requestOpts)

	switch {
	case requestOpts.credentialID != "":
		raw, err := c.contents.Get(authToken, requestOpts.credentialID, Credential)
		if err != nil {
			return false, fmt.Errorf("failed to get credential: %w", err)
		}

		return c.verifyCredential(authToken, raw)
	case len(requestOpts.rawCredential) > 0:
		return c.verifyCredential(authToken, requestOpts.rawCredential)
	case len(requestOpts.rawPresentation) > 0:
		return c.verifyPresentation(authToken, requestOpts.rawPresentation)
	default:
		return false, fmt.Errorf("invalid verify request")
	}
}

// Derive derives a credential and returns response credential.
//
//	Args:
//		- credential to derive (ID of the stored credential, raw credential or credential instance).
//		- derive options.
//
func (c *Wallet) Derive(authToken string, credential CredentialToDerive, options *DeriveOptions) (*verifiable.Credential, error) { //nolint: lll
	vc, err := c.resolveCredentialToDerive(authToken, credential)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve request : %w", err)
	}

	derived, err := vc.GenerateBBSSelectiveDisclosure(options.Frame, []byte(options.Nonce),
		verifiable.WithPublicKeyFetcher(
			verifiable.NewVDRKeyResolver(newContentBasedVDR(authToken, c.vdr, c.contents)).PublicKeyFetcher(),
		), verifiable.WithJSONLDDocumentLoader(c.jsonldDocumentLoader))
	if err != nil {
		return nil, fmt.Errorf("failed to derive credential : %w", err)
	}

	return derived, nil
}

// CreateKeyPair creates key pair inside a wallet.
//
//	Args:
//		- authToken: authorization for performing create key pair operation.
//		- keyType: type of the key to be created.
//
func (c *Wallet) CreateKeyPair(authToken string, keyType kms.KeyType) (*KeyPair, error) {
	kmgr, err := keyManager().getKeyManger(authToken)
	if err != nil {
		return nil, ErrInvalidAuthToken
	}

	kid, pubBytes, err := kmgr.CreateAndExportPubKeyBytes(keyType)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		KeyID:     kid,
		PublicKey: base64.RawURLEncoding.EncodeToString(pubBytes),
	}, nil
}

// Connect accepts out-of-band invitations and performs DID exchange.
//
// Args:
// 		- authToken: authorization for performing create key pair operation.
// 		- invitation: out-of-band invitation.
// 		- options: connection options.
//
// Returns:
// 		- connection ID if DID exchange is successful.
// 		- error if operation false.
//
func (c *Wallet) Connect(authToken string, invitation *outofband.Invitation, options ...ConnectOptions) (string, error) { //nolint: lll
	statusCh := make(chan service.StateMsg, msgEventBufferSize)

	err := c.didexchangeClient.RegisterMsgEvent(statusCh)
	if err != nil {
		return "", fmt.Errorf("failed to register msg event : %w", err)
	}

	defer func() {
		e := c.didexchangeClient.UnregisterMsgEvent(statusCh)
		if e != nil {
			logger.Warnf("Failed to unregister msg event for connect: %w", e)
		}
	}()

	opts := &connectOpts{}
	for _, opt := range options {
		opt(opts)
	}

	connID, err := c.oobClient.AcceptInvitation(invitation, opts.Label, getOobMessageOptions(opts)...)
	if err != nil {
		return "", fmt.Errorf("failed to accept invitation : %w", err)
	}

	if opts.timeout == 0 {
		opts.timeout = defaultDIDExchangeTimeOut
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()

	err = waitForConnect(ctx, statusCh, connID)
	if err != nil {
		return "", fmt.Errorf("wallet connect failed : %w", err)
	}

	return connID, nil
}

// ProposePresentation accepts out-of-band invitation and sends message proposing presentation
// from wallet to relying party.
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#proposepresentation
//
// Currently Supporting
// [0454-present-proof-v2](https://github.com/hyperledger/aries-rfcs/tree/master/features/0454-present-proof-v2)
//
// Args:
// 		- authToken: authorization for performing operation.
// 		- invitation: out-of-band invitation from relying party.
// 		- options: options for accepting invitation and send propose presentation message.
//
// Returns:
// 		- DIDCommMsgMap containing request presentation message if operation is successful.
// 		- error if operation fails.
//
func (c *Wallet) ProposePresentation(authToken string, invitation *GenericInvitation, options ...InitiateInteractionOption) (*service.DIDCommMsgMap, error) { //nolint: lll
	opts := &initiateInteractionOpts{}
	for _, opt := range options {
		opt(opts)
	}

	var (
		connID string
		err    error
	)

	switch invitation.Version() {
	default:
		fallthrough
	case service.V1:
		connID, err = c.Connect(authToken, (*outofband.Invitation)(invitation.AsV1()), opts.connectOpts...)
		if err != nil {
			return nil, fmt.Errorf("failed to perform did connection : %w", err)
		}
	case service.V2:
		connID, err = c.oobV2Client.AcceptInvitation(invitation.AsV2())
		if err != nil {
			return nil, fmt.Errorf("failed to accept OOB v2 invitation : %w", err)
		}
	}

	connRecord, err := c.connectionLookup.GetConnectionRecord(connID)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup connection for propose presentation : %w", err)
	}

	opts = prepareInteractionOpts(connRecord, opts)

	_, err = c.presentProofClient.SendProposePresentation(&presentproof.ProposePresentation{}, connRecord)
	if err != nil {
		return nil, fmt.Errorf("failed to propose presentation from wallet: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()

	return c.waitForRequestPresentation(ctx, connRecord)
}

// PresentProof sends message present proof message from wallet to relying party.
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#presentproof
//
// Currently Supporting
// [0454-present-proof-v2](https://github.com/hyperledger/aries-rfcs/tree/master/features/0454-present-proof-v2)
//
// Args:
// 		- authToken: authorization for performing operation.
// 		- thID: thread ID (action ID) of request presentation.
// 		- presentProofFrom: presentation to be sent.
//
// Returns:
// 		- Credential interaction status containing status, redirectURL.
// 		- error if operation fails.
//
func (c *Wallet) PresentProof(authToken, thID string, options ...ConcludeInteractionOptions) (*CredentialInteractionStatus, error) { //nolint: lll
	opts := &concludeInteractionOpts{}

	for _, option := range options {
		option(opts)
	}

	var presentation interface{}
	if opts.presentation != nil {
		presentation = opts.presentation
	} else {
		presentation = opts.rawPresentation
	}

	err := c.presentProofClient.AcceptRequestPresentation(thID, &presentproof.Presentation{
		Attachments: []decorator.GenericAttachment{{
			ID: uuid.New().String(),
			Data: decorator.AttachmentData{
				JSON: presentation,
			},
		}},
	}, nil)
	if err != nil {
		return nil, err
	}

	// wait for ack or problem-report.
	if opts.waitForDone {
		statusCh := make(chan service.StateMsg, msgEventBufferSize)

		err = c.presentProofClient.RegisterMsgEvent(statusCh)
		if err != nil {
			return nil, fmt.Errorf("failed to register present proof msg event : %w", err)
		}

		defer func() {
			e := c.presentProofClient.UnregisterMsgEvent(statusCh)
			if e != nil {
				logger.Warnf("Failed to unregister msg event for present proof: %w", e)
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
		defer cancel()

		return waitCredInteractionCompletion(ctx, statusCh, thID)
	}

	return &CredentialInteractionStatus{Status: model.AckStatusPENDING}, nil
}

// ProposeCredential sends propose credential message from wallet to issuer.
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#proposecredential
//
// Currently Supporting : 0453-issueCredentialV2
// https://github.com/hyperledger/aries-rfcs/blob/main/features/0453-issue-credential-v2/README.md
//
// Args:
// 		- authToken: authorization for performing operation.
// 		- invitation: out-of-band invitation from issuer.
// 		- options: options for accepting invitation and send propose credential message.
//
// Returns:
// 		- DIDCommMsgMap containing offer credential message if operation is successful.
// 		- error if operation fails.
//
func (c *Wallet) ProposeCredential(authToken string, invitation *GenericInvitation, options ...InitiateInteractionOption) (*service.DIDCommMsgMap, error) { //nolint: lll
	opts := &initiateInteractionOpts{}
	for _, opt := range options {
		opt(opts)
	}

	var (
		connID string
		err    error
	)

	switch invitation.Version() {
	default:
		fallthrough
	case service.V1:
		connID, err = c.Connect(authToken, (*outofband.Invitation)(invitation.AsV1()), opts.connectOpts...)
		if err != nil {
			return nil, fmt.Errorf("failed to perform did connection : %w", err)
		}
	case service.V2:
		connID, err = c.oobV2Client.AcceptInvitation(invitation.AsV2())
		if err != nil {
			return nil, fmt.Errorf("failed to accept OOB v2 invitation : %w", err)
		}
	}

	connRecord, err := c.connectionLookup.GetConnectionRecord(connID)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup connection for propose presentation : %w", err)
	}

	opts = prepareInteractionOpts(connRecord, opts)

	_, err = c.issueCredentialClient.SendProposal(
		&issuecredential.ProposeCredential{InvitationID: invitation.ID},
		connRecord,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to propose credential from wallet: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()

	return c.waitForOfferCredential(ctx, connRecord)
}

// RequestCredential sends request credential message from wallet to issuer and
// optionally waits for credential fulfillment.
// https://w3c-ccg.github.io/universal-wallet-interop-spec/#requestcredential
//
// Currently Supporting : 0453-issueCredentialV2
// https://github.com/hyperledger/aries-rfcs/blob/main/features/0453-issue-credential-v2/README.md
//
// Args:
// 		- authToken: authorization for performing operation.
// 		- thID: thread ID (action ID) of offer credential message previously received.
// 		- concludeInteractionOptions: options to conclude interaction like presentation to be shared etc.
//
// Returns:
// 		- Credential interaction status containing status, redirectURL.
// 		- error if operation fails.
//
func (c *Wallet) RequestCredential(authToken, thID string, options ...ConcludeInteractionOptions) (*CredentialInteractionStatus, error) { //nolint: lll
	opts := &concludeInteractionOpts{}

	for _, option := range options {
		option(opts)
	}

	var presentation interface{}
	if opts.presentation != nil {
		presentation = opts.presentation
	} else {
		presentation = opts.rawPresentation
	}

	attachmentID := uuid.New().String()

	err := c.issueCredentialClient.AcceptOffer(thID, &issuecredential.RequestCredential{
		Type: issuecredentialsvc.RequestCredentialMsgTypeV2,
		Formats: []issuecredentialsvc.Format{{
			AttachID: attachmentID,
			Format:   ldJSONMimeType,
		}},
		Attachments: []decorator.GenericAttachment{{
			ID: attachmentID,
			Data: decorator.AttachmentData{
				JSON: presentation,
			},
		}},
	})
	if err != nil {
		return nil, err
	}

	// wait for credential fulfillment.
	if opts.waitForDone {
		statusCh := make(chan service.StateMsg, msgEventBufferSize)

		err = c.issueCredentialClient.RegisterMsgEvent(statusCh)
		if err != nil {
			return nil, fmt.Errorf("failed to register issue credential action event : %w", err)
		}

		defer func() {
			e := c.issueCredentialClient.UnregisterMsgEvent(statusCh)
			if e != nil {
				logger.Warnf("Failed to unregister action event for issue credential: %w", e)
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
		defer cancel()

		return waitCredInteractionCompletion(ctx, statusCh, thID)
	}

	return &CredentialInteractionStatus{Status: model.AckStatusPENDING}, nil
}

//nolint: funlen,gocyclo
func (c *Wallet) resolveOptionsToPresent(auth string, credentials ...ProveOptions) (*verifiable.Presentation, error) {
	var allCredentials []*verifiable.Credential

	opts := &proveOpts{}

	for _, opt := range credentials {
		opt(opts)
	}

	for _, id := range opts.storedCredentials {
		raw, err := c.contents.Get(auth, id, Credential)
		if err != nil {
			return nil, err
		}

		// proof check is disabled while resolving credentials from store. A wallet UI may or may not choose to
		// show credentials as verified. If a wallet implementation chooses to show credentials as 'verified' it
		// may to call 'wallet.Verify()' for each credential being presented.
		// (More details can be found in issue #2677).
		credential, err := verifiable.ParseCredential(raw, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(c.jsonldDocumentLoader))
		if err != nil {
			return nil, err
		}

		allCredentials = append(allCredentials, credential)
	}

	for _, raw := range opts.rawCredentials {
		// proof check is disabled while resolving credentials from raw bytes. A wallet UI may or may not choose to
		// show credentials as verified. If a wallet implementation chooses to show credentials as 'verified' it
		// may to call 'wallet.Verify()' for each credential being presented.
		// (More details can be found in issue #2677).
		credential, err := verifiable.ParseCredential(raw, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(c.jsonldDocumentLoader))
		if err != nil {
			return nil, err
		}

		allCredentials = append(allCredentials, credential)
	}

	if len(opts.credentials) > 0 {
		allCredentials = append(allCredentials, opts.credentials...)
	}

	if opts.presentation != nil {
		opts.presentation.AddCredentials(allCredentials...)

		return opts.presentation, nil
	} else if len(opts.rawPresentation) > emptyRawLength {
		vp, err := verifiable.ParsePresentation(opts.rawPresentation, verifiable.WithPresDisabledProofCheck(),
			verifiable.WithPresJSONLDDocumentLoader(c.jsonldDocumentLoader))
		if err != nil {
			return nil, err
		}

		vp.AddCredentials(allCredentials...)

		return vp, nil
	}

	return verifiable.NewPresentation(verifiable.WithCredentials(allCredentials...))
}

func (c *Wallet) resolveCredentialToDerive(auth string, credential CredentialToDerive) (*verifiable.Credential, error) {
	opts := &deriveOpts{}

	credential(opts)

	if opts.credential != nil {
		return opts.credential, nil
	}

	if len(opts.rawCredential) > 0 {
		// proof check is disabled while resolving credentials from store. A wallet UI may or may not choose to
		// show credentials as verified. If a wallet implementation chooses to show credentials as 'verified' it
		// may to call 'wallet.Verify()' for each credential being presented.
		// (More details can be found in issue #2677).
		return verifiable.ParseCredential(opts.rawCredential, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(c.jsonldDocumentLoader))
	}

	if opts.credentialID != "" {
		raw, err := c.contents.Get(auth, opts.credentialID, Credential)
		if err != nil {
			return nil, err
		}

		// proof check is disabled while resolving credentials from store. A wallet UI may or may not choose to
		// show credentials as verified. If a wallet implementation chooses to show credentials as 'verified' it
		// may to call 'wallet.Verify()' for each credential being presented.
		// (More details can be found in issue #2677).
		return verifiable.ParseCredential(raw, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(c.jsonldDocumentLoader))
	}

	return nil, errors.New("invalid request to derive credential")
}

func (c *Wallet) verifyCredential(authToken string, credential json.RawMessage) (bool, error) {
	_, err := verifiable.ParseCredential(credential, verifiable.WithPublicKeyFetcher(
		verifiable.NewVDRKeyResolver(newContentBasedVDR(authToken, c.vdr, c.contents)).PublicKeyFetcher(),
	), verifiable.WithJSONLDDocumentLoader(c.jsonldDocumentLoader))
	if err != nil {
		return false, fmt.Errorf("credential verification failed: %w", err)
	}

	return true, nil
}

func (c *Wallet) verifyPresentation(authToken string, presentation json.RawMessage) (bool, error) {
	vp, err := verifiable.ParsePresentation(presentation, verifiable.WithPresPublicKeyFetcher(
		verifiable.NewVDRKeyResolver(newContentBasedVDR(authToken, c.vdr, c.contents)).PublicKeyFetcher(),
	), verifiable.WithPresJSONLDDocumentLoader(c.jsonldDocumentLoader))
	if err != nil {
		return false, fmt.Errorf("presentation verification failed: %w", err)
	}

	// verify proof of each credential
	for _, cred := range vp.Credentials() {
		vc, err := json.Marshal(cred)
		if err != nil {
			return false, fmt.Errorf("failed to read credentials from presentation: %w", err)
		}

		_, err = c.verifyCredential(authToken, vc)
		if err != nil {
			return false, fmt.Errorf("presentation verification failed: %w", err)
		}
	}

	return true, nil
}

func (c *Wallet) addLinkedDataProof(authToken string, p provable, opts *ProofOptions,
	relationship did.VerificationRelationship) error {
	s, err := newKMSSigner(authToken, c.walletCrypto, opts)
	if err != nil {
		return err
	}

	var signatureSuite signer.SignatureSuite

	switch opts.ProofType {
	case Ed25519Signature2018:
		signatureSuite = ed25519signature2018.New(suite.WithSigner(s))
	case JSONWebSignature2020:
		signatureSuite = jsonwebsignature2020.New(suite.WithSigner(s))
	case BbsBlsSignature2020:
		addContext(p, bbsContext)

		signatureSuite = bbsblssignature2020.New(suite.WithSigner(s))
	default:
		return fmt.Errorf("unsupported signature type '%s'", opts.ProofType)
	}

	signingCtx := &verifiable.LinkedDataProofContext{
		VerificationMethod:      opts.VerificationMethod,
		SignatureRepresentation: *opts.ProofRepresentation,
		SignatureType:           opts.ProofType,
		Suite:                   signatureSuite,
		Created:                 opts.Created,
		Domain:                  opts.Domain,
		Challenge:               opts.Challenge,
		Purpose:                 supportedRelationships[relationship],
	}

	err = p.AddLinkedDataProof(signingCtx, jsonld.WithDocumentLoader(c.jsonldDocumentLoader))
	if err != nil {
		return fmt.Errorf("failed to add linked data proof: %w", err)
	}

	return nil
}

func (c *Wallet) validateProofOption(authToken string, opts *ProofOptions, method did.VerificationRelationship) error {
	if opts == nil || opts.Controller == "" {
		return errors.New("invalid proof option, 'controller' is required")
	}

	resolvedDoc, err := newContentBasedVDR(authToken, c.vdr, c.contents).Resolve(opts.Controller)
	if err != nil {
		return err
	}

	err = c.validateVerificationMethod(resolvedDoc.DIDDocument, opts, method)
	if err != nil {
		return err
	}

	if opts.ProofRepresentation == nil {
		opts.ProofRepresentation = &defaultSignatureRepresentation
	}

	if opts.ProofType == "" {
		opts.ProofType = Ed25519Signature2018
	}

	return nil
}

func (c *Wallet) validateVerificationMethod(didDoc *did.Doc, opts *ProofOptions,
	relationship did.VerificationRelationship) error {
	vms := didDoc.VerificationMethods(relationship)[relationship]

	for _, vm := range vms {
		if opts.VerificationMethod == "" {
			opts.VerificationMethod = vm.VerificationMethod.ID
			return nil
		}

		if opts.VerificationMethod == vm.VerificationMethod.ID {
			return nil
		}
	}

	return fmt.Errorf("unable to find '%s' for given verification method", supportedRelationships[relationship])
}

// currently correlating response action by connection due to limitation in current present proof V1 implementation.
func (c *Wallet) waitForRequestPresentation(ctx context.Context, record *connection.Record) (*service.DIDCommMsgMap, error) { //nolint: lll
	done := make(chan *service.DIDCommMsgMap)

	go func() {
		for {
			actions, err := c.presentProofClient.Actions()
			if err != nil {
				continue
			}

			if len(actions) > 0 {
				for _, action := range actions {
					if action.MyDID == record.MyDID && action.TheirDID == record.TheirDID {
						done <- &action.Msg
						return
					}
				}
			}

			select {
			default:
				time.Sleep(retryDelay)
			case <-ctx.Done():
				return
			}
		}
	}()

	select {
	case msg := <-done:
		return msg, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout waiting for request presentation message")
	}
}

// currently correlating response action by connection due to limitation in current issue credential V1 implementation.
func (c *Wallet) waitForOfferCredential(ctx context.Context, record *connection.Record) (*service.DIDCommMsgMap, error) { //nolint: lll
	done := make(chan *service.DIDCommMsgMap)

	go func() {
		for {
			actions, err := c.issueCredentialClient.Actions()
			if err != nil {
				continue
			}

			if len(actions) > 0 {
				for _, action := range actions {
					if action.MyDID == record.MyDID && action.TheirDID == record.TheirDID {
						done <- &action.Msg
						return
					}
				}
			}

			select {
			default:
				time.Sleep(retryDelay)
			case <-ctx.Done():
				return
			}
		}
	}()

	select {
	case msg := <-done:
		return msg, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout waiting for offer credential message")
	}
}

func waitForConnect(ctx context.Context, didStateMsgs chan service.StateMsg, connID string) error {
	done := make(chan struct{})

	go func() {
		for msg := range didStateMsgs {
			if msg.Type != service.PostState || msg.StateID != didexchangeSvc.StateIDCompleted {
				continue
			}

			var event didexchangeSvc.Event

			switch p := msg.Properties.(type) {
			case didexchangeSvc.Event:
				event = p
			default:
				logger.Warnf("failed to cast didexchange event properties")

				continue
			}

			if event.ConnectionID() == connID {
				logger.Debugf(
					"Received connection complete event for invitationID=%s connectionID=%s",
					event.InvitationID(), event.ConnectionID())

				close(done)

				break
			}
		}
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("time out waiting for did exchange state 'completed'")
	}
}

// wait for credential interaction to be completed (done or abandoned protocol state).
func waitCredInteractionCompletion(ctx context.Context, didStateMsgs chan service.StateMsg, thID string) (*CredentialInteractionStatus, error) { // nolint:gocognit,gocyclo,lll
	done := make(chan *CredentialInteractionStatus)

	go func() {
		for msg := range didStateMsgs {
			// match post state.
			if msg.Type != service.PostState {
				continue
			}

			// invalid state msg.
			if msg.Msg == nil {
				continue
			}

			msgThID, err := msg.Msg.ThreadID()
			if err != nil {
				continue
			}

			// match parent thread ID.
			if msg.Msg.ParentThreadID() != thID && msgThID != thID {
				continue
			}

			// match protocol state.
			if msg.StateID != stateNameDone && msg.StateID != stateNameAbandoned && msg.StateID != stateNameAbandoning {
				continue
			}

			properties := msg.Properties.All()

			response := &CredentialInteractionStatus{}
			response.RedirectURL, response.Status = getWebRedirectInfo(properties)

			// if redirect status missing, then use protocol state, done -> OK, abandoned -> FAIL.
			if response.Status == "" {
				if msg.StateID == stateNameAbandoned || msg.StateID == stateNameAbandoning {
					response.Status = model.AckStatusFAIL
				} else {
					response.Status = model.AckStatusOK
				}
			}

			done <- response

			return
		}
	}()

	select {
	case status := <-done:
		return status, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("time out waiting for credential interaction to get completed")
	}
}

// addContext adds context if not found in given data model.
func addContext(v interface{}, ldcontext string) {
	if vc, ok := v.(*verifiable.Credential); ok {
		for _, ctx := range vc.Context {
			if ctx == ldcontext {
				return
			}
		}

		vc.Context = append(vc.Context, ldcontext)
	}
}

func updateProfile(auth string, profile *profile) error {
	// get key manager
	keyManager, err := keyManager().getKeyManger(auth)
	if err != nil {
		return err
	}

	// setup key pairs
	err = profile.setupEDVEncryptionKey(keyManager)
	if err != nil {
		return fmt.Errorf("failed to create EDV encryption key pair: %w", err)
	}

	err = profile.setupEDVMacKey(keyManager)
	if err != nil {
		return fmt.Errorf("failed to create EDV MAC key pair: %w", err)
	}

	return nil
}

func prepareInteractionOpts(connRecord *connection.Record, opts *initiateInteractionOpts) *initiateInteractionOpts {
	if opts.from == "" {
		opts.from = connRecord.TheirDID
	}

	if opts.timeout == 0 {
		opts.timeout = defaultWaitForRequestPresentationTimeOut
	}

	return opts
}

// getWebRedirectInfo reads web redirect info from properties.
func getWebRedirectInfo(properties map[string]interface{}) (string, string) {
	var redirect, status string

	if redirectURL, ok := properties[webRedirectURLKey]; ok {
		redirect = redirectURL.(string) //nolint: errcheck, forcetypeassert
	}

	if redirectStatus, ok := properties[webRedirectStatusKey]; ok {
		status = redirectStatus.(string) //nolint: errcheck, forcetypeassert
	}

	return redirect, status
}
