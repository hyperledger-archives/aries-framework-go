/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/cm"
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
	bbsContext     = "https://w3id.org/security/bbs/v1"
	emptyRawLength = 4

	// web redirect constants.
	webRedirectStatusKey = "status"
	webRedirectURLKey    = "url"
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
}

type provable interface {
	AddLinkedDataProof(context *verifiable.LinkedDataProofContext, jsonldOpts ...jsonld.ProcessorOpts) error
}

type jwtClaims interface {
	MarshalJWS(signatureAlg verifiable.JWSAlgorithm, signer verifiable.Signer, keyID string) (string, error)
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

	return &Wallet{
		userID:               userID,
		profile:              profile,
		storeProvider:        ctx.StorageProvider(),
		walletCrypto:         ctx.Crypto(),
		contents:             newContentStore(ctx.StorageProvider(), ctx.JSONLDDocumentLoader(), profile),
		vdr:                  ctx.VDRegistry(),
		jsonldDocumentLoader: ctx.JSONLDDocumentLoader(),
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

	kmsStore, err := kms.NewAriesProviderWrapper(ctx.StorageProvider())
	if err != nil {
		return err
	}

	// unlock key manager
	kmsm, err := keyManager().createKeyManager(profile, kmsStore, opts)
	if err != nil {
		return fmt.Errorf("failed to get key manager: %w", err)
	}

	// update profile
	err = updateProfile(kmsm, profile)
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

	kmsStore, err := kms.NewAriesProviderWrapper(c.storeProvider)
	if err != nil {
		return "", err
	}

	// unlock key manager
	keyManager, err := keyManager().createKeyManager(c.profile, kmsStore, opts)
	if err != nil {
		return "", err
	}

	token, err := sessionManager().createSession(c.profile.User, keyManager, opts.tokenExpiry)
	if err != nil {
		return "", err
	}

	// open content store using token
	err = c.contents.Open(keyManager, opts)
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
	return sessionManager().closeSession(c.userID) && c.contents.Close()
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
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
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
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Key
func (c *Wallet) Import(auth string, contents json.RawMessage) error {
	// TODO to be added #2433
	return fmt.Errorf("to be implemented")
}

// Add adds given data model to wallet contents store.
//
// Supported data models:
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Key
func (c *Wallet) Add(authToken string, contentType ContentType, content json.RawMessage, options ...AddContentOptions) error { //nolint: lll
	return c.contents.Save(authToken, contentType, content, options...)
}

// Remove removes wallet content by content ID.
//
// Supported data models:
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
func (c *Wallet) Remove(authToken string, contentType ContentType, contentID string) error {
	return c.contents.Remove(authToken, contentID, contentType)
}

// Get fetches a wallet content by content ID.
//
// Supported data models:
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
func (c *Wallet) Get(authToken string, contentType ContentType, contentID string) (json.RawMessage, error) {
	return c.contents.Get(authToken, contentID, contentType)
}

// GetAll fetches all wallet contents of given type.
// Returns map of key value from content store for given content type.
//
// Supported data models:
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Collection
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#DIDResolutionResponse
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//   - https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
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
//   - https://www.w3.org/TR/json-ld11-framing
//   - https://identity.foundation/presentation-exchange
//   - https://w3c-ccg.github.io/vp-request-spec/#query-by-example
//   - https://w3c-ccg.github.io/vp-request-spec/#did-authentication-request
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

	switch options.ProofFormat {
	case ExternalJWTProofFormat:
		claims, e := vc.JWTClaims(false)
		if e != nil {
			return nil, fmt.Errorf("failed to generate JWT claims for VC: %w", e)
		}

		jws, e := c.verifiableClaimsToJWT(authToken, claims, options)
		if e != nil {
			return nil, fmt.Errorf("failed to generate JWT VC: %w", e)
		}

		vc.JWT = jws
	default: // default case is EmbeddedLDProofFormat
		err = c.addLinkedDataProof(authToken, vc, options, purpose)
		if err != nil {
			return nil, fmt.Errorf("failed to issue credential: %w", err)
		}
	}

	return vc, nil
}

// Prove produces a Verifiable Presentation.
//
//	Args:
//		- auth token for unlocking kms.
//		- list of interfaces (string of credential IDs which can be resolvable to stored credentials in wallet or
//		raw credential or a presentation).
//		- proof options
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

	switch proofOptions.ProofFormat {
	case ExternalJWTProofFormat:
		// TODO: look into passing audience identifier
		//  https://github.com/hyperledger/aries-framework-go/issues/3354
		claims, e := presentation.JWTClaims(nil, false)
		if e != nil {
			return nil, fmt.Errorf("failed to generate JWT claims for VP: %w", e)
		}

		jws, e := c.verifiableClaimsToJWT(authToken, claims, proofOptions)
		if e != nil {
			return nil, fmt.Errorf("failed to generate JWT VP: %w", e)
		}

		presentation.JWT = jws
	default: // default case is EmbeddedLDProofFormat
		err = c.addLinkedDataProof(authToken, presentation, proofOptions, purpose)
		if err != nil {
			return nil, fmt.Errorf("failed to prove credentials: %w", err)
		}
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
func (c *Wallet) CreateKeyPair(authToken string, keyType kms.KeyType) (*KeyPair, error) {
	session, err := sessionManager().getSession(authToken)
	if err != nil {
		return nil, err
	}

	kid, pubBytes, err := session.KeyManager.CreateAndExportPubKeyBytes(keyType)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		KeyID:     kid,
		PublicKey: base64.RawURLEncoding.EncodeToString(pubBytes),
	}, nil
}

// ResolveCredentialManifest resolves given credential manifest by credential response or credential.
// Supports: https://identity.foundation/credential-manifest/
//
// Args:
//   - authToken: authorization for performing operation.
//   - manifest: Credential manifest data model in raw format.
//   - resolve: options to provide credential response or credential to resolve.
//
// Returns:
//   - list of resolved descriptors.
//   - error if operation fails.
func (c *Wallet) ResolveCredentialManifest(authToken string, manifest json.RawMessage, resolve ResolveManifestOption) ([]*cm.ResolvedDescriptor, error) { //nolint: lll,gocyclo
	credentialManifest := &cm.CredentialManifest{}

	err := credentialManifest.UnmarshalJSON(manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to read credential manifest: %w", err)
	}

	opts := &resolveManifestOpts{}

	if resolve != nil {
		resolve(opts)
	}

	switch {
	case len(opts.rawResponse) > 0:
		opts.response, err = verifiable.ParsePresentation(opts.rawResponse,
			verifiable.WithPresDisabledProofCheck(),
			verifiable.WithPresJSONLDDocumentLoader(c.jsonldDocumentLoader))
		if err != nil {
			return nil, err
		}

		fallthrough
	case opts.response != nil:
		return credentialManifest.ResolveResponse(opts.response)
	case opts.credentialID != "":
		opts.rawCredential, err = c.Get(authToken, Credential, opts.credentialID)
		if err != nil {
			return nil, fmt.Errorf("failed to get credential to resolve from wallet: %w", err)
		}

		fallthrough
	case len(opts.rawCredential) > 0:
		opts.credential, err = verifiable.ParseCredential(opts.rawCredential, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(c.jsonldDocumentLoader))
		if err != nil {
			return nil, err
		}

		resolved, err := credentialManifest.ResolveCredential(opts.descriptorID,
			cm.RawCredentialToResolve(opts.rawCredential))
		if err != nil {
			return nil, fmt.Errorf("failed to resolve raw credential by descriptor ID '%s':  %w",
				opts.descriptorID, err)
		}

		return []*cm.ResolvedDescriptor{resolved}, nil
	case opts.credential != nil:
		resolved, err := credentialManifest.ResolveCredential(opts.descriptorID,
			cm.CredentialToResolve(opts.credential))
		if err != nil {
			return nil, fmt.Errorf("failed to resolve given credential by descriptor ID '%s' : %w",
				opts.descriptorID, err)
		}

		return []*cm.ResolvedDescriptor{resolved}, nil
	default:
		return nil, errors.New("failed to resolve credential manifest, invalid option")
	}
}

// nolint: funlen,gocyclo
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

func (c *Wallet) verifiableClaimsToJWT(authToken string, claims jwtClaims, options *ProofOptions) (string, error) {
	s, err := newKMSSigner(authToken, c.walletCrypto, options)
	if err != nil {
		return "", fmt.Errorf("initializing signer: %w", err)
	}

	var alg verifiable.JWSAlgorithm

	switch s.KeyType {
	case kms.ED25519Type:
		alg = verifiable.EdDSA
	case kms.ECDSAP256TypeIEEEP1363:
		alg = verifiable.ECDSASecp256r1
	case kms.ECDSAP384TypeIEEEP1363:
		alg = verifiable.ECDSASecp384r1
	case kms.ECDSAP521TypeIEEEP1363:
		alg = verifiable.ECDSASecp521r1
	default:
		return "", fmt.Errorf("unsupported keytype for JWT")
	}

	jws, err := claims.MarshalJWS(alg, s, options.VerificationMethod)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWS: %w", err)
	}

	return jws, nil
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

	if opts.ProofFormat == "" {
		opts.ProofFormat = EmbeddedLDProofFormat
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

func updateProfile(keyManager kms.KeyManager, profile *profile) error {
	// setup key pairs
	err := profile.setupEDVEncryptionKey(keyManager)
	if err != nil {
		return fmt.Errorf("failed to create EDV encryption key pair: %w", err)
	}

	err = profile.setupEDVMacKey(keyManager)
	if err != nil {
		return fmt.Errorf("failed to create EDV MAC key pair: %w", err)
	}

	return nil
}
