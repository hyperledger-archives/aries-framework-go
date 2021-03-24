/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	jld "github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
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
	bbsContext = "https://w3id.org/security/bbs/v1"
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

// provider contains dependencies for the verifiable credential wallet
// and is typically created by using aries.Context().
type provider interface {
	StorageProvider() storage.Provider
	VDRegistry() vdr.Registry
	Crypto() crypto.Crypto
}

type provable interface {
	AddLinkedDataProof(context *verifiable.LinkedDataProofContext, jsonldOpts ...jsonld.ProcessorOpts) error
}

// kmsOpts contains options for creating verifiable credential wallet.
type kmsOpts struct {
	// local kms options
	secretLockSvc secretlock.Service
	passphrase    string

	// remote(web) kms options
	keyServerURL string
}

// ProfileKeyManagerOptions is option for verifiable credential wallet key manager.
type ProfileKeyManagerOptions func(opts *kmsOpts)

// WithSecretLockService option, when provided then wallet will use local kms for key operations.
func WithSecretLockService(svc secretlock.Service) ProfileKeyManagerOptions {
	return func(opts *kmsOpts) {
		opts.secretLockSvc = svc
	}
}

// WithPassphrase option to provide passphrase for local kms for key operations.
func WithPassphrase(passphrase string) ProfileKeyManagerOptions {
	return func(opts *kmsOpts) {
		opts.passphrase = passphrase
	}
}

// WithKeyServerURL option, when provided then wallet will use remote kms for key operations.
// This option will be ignore if provided with 'WithSecretLockService' option.
func WithKeyServerURL(url string) ProfileKeyManagerOptions {
	return func(opts *kmsOpts) {
		opts.keyServerURL = url
	}
}

// unlockOpts contains options for unlocking VC wallet client.
type unlockOpts struct {
	// local kms options
	passphrase    string
	secretLockSvc secretlock.Service

	// remote(web) kms options
	authToken string

	// expiry
	tokenExpiry time.Duration
}

// UnlockOptions is option for unlocking verifiable credential wallet key manager.
// Wallet unlocking instantiates KMS instance for wallet operations.
// Type of key manager (local or remote) to be used will be decided based on options passed.
// Note: unlock options should match key manager options set for given wallet profile.
type UnlockOptions func(opts *unlockOpts)

// WithUnlockByPassphrase option for supplying passphrase to open wallet.
// This option takes precedence when provided along with other options.
func WithUnlockByPassphrase(passphrase string) UnlockOptions {
	return func(opts *unlockOpts) {
		opts.passphrase = passphrase
	}
}

// WithUnlockBySecretLockService option for supplying secret lock service to open wallet.
// This option will be ignored when supplied with 'WithPassphrase' option.
func WithUnlockBySecretLockService(svc secretlock.Service) UnlockOptions {
	return func(opts *unlockOpts) {
		opts.secretLockSvc = svc
	}
}

// WithUnlockByAuthorizationToken option for supplying remote kms auth token to open wallet.
// This option will be ignore when supplied with localkms options.
func WithUnlockByAuthorizationToken(url string) UnlockOptions {
	return func(opts *unlockOpts) {
		opts.authToken = url
	}
}

// WithUnlockExpiry time duration after which wallet key manager will be expired.
// Wallet should be reopened by using 'client.Open()' once expired or a new instance needs to be created.
func WithUnlockExpiry(tokenExpiry time.Duration) UnlockOptions {
	return func(opts *unlockOpts) {
		opts.tokenExpiry = tokenExpiry
	}
}

// Wallet enables access to verifiable credential wallet features.
type Wallet struct {
	// ID of wallet content owner
	userID string

	// wallet profile
	profile *profile

	// wallet content store
	contents *contentStore

	// storage provider
	ctx provider
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

	contents, err := newContentStore(ctx.StorageProvider(), profile)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet content store: %w", err)
	}

	return &Wallet{userID: userID, profile: profile, ctx: ctx, contents: contents}, nil
}

// CreateProfile creates a new verifiable credential wallet profile for given user.
// returns error if wallet profile is already created.
// Use `UpdateProfile()` for replacing an already created verifiable credential wallet profile.
func CreateProfile(userID string, ctx provider, options ...ProfileKeyManagerOptions) error {
	return createOrUpdate(userID, ctx, false, options...)
}

// UpdateProfile updates existing verifiable credential wallet profile.
// Will create new profile if no profile exists for given user.
// Caution: you might lose your existing keys if you change kms options.
func UpdateProfile(userID string, ctx provider, options ...ProfileKeyManagerOptions) error {
	return createOrUpdate(userID, ctx, true, options...)
}

func createOrUpdate(userID string, ctx provider, update bool, options ...ProfileKeyManagerOptions) error {
	opts := &kmsOpts{}

	for _, opt := range options {
		opt(opts)
	}

	store, err := newProfileStore(ctx.StorageProvider())
	if err != nil {
		return fmt.Errorf("failed to get store to save VC wallet profile: %w", err)
	}

	var profile *profile

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
	} else {
		// create new profile.
		profile, err = createProfile(userID, opts.passphrase, opts.secretLockSvc, opts.keyServerURL)
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

// Open unlocks wallet's key manager instance and returns a token for subsequent use of wallet features.
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

	return keyManager().createKeyManager(c.profile, c.ctx.StorageProvider(), opts)
}

// Close expires token issued to this VC wallet.
// returns false if token is not found or already expired for this wallet user.
func (c *Wallet) Close() bool {
	return keyManager().removeKeyManager(c.userID)
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
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Profile
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
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
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Profile
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#CachedDIDDocument
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//
func (c *Wallet) Import(auth string, contents json.RawMessage) error {
	// TODO to be added #2433
	return fmt.Errorf("to be implemented")
}

// Add adds given data model to wallet contents store.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Profile
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#CachedDIDDocument
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//
// TODO: (#2433) support for correlation between wallet contents (ex: credentials to a profile/collection).
func (c *Wallet) Add(contentType ContentType, content json.RawMessage) error {
	return c.contents.Save(contentType, content)
}

// Remove removes wallet content by content ID.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Profile
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#CachedDIDDocument
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//
func (c *Wallet) Remove(contentType ContentType, contentID string) error {
	return c.contents.Remove(contentType, contentID)
}

// Get fetches a wallet content by content ID.
//
// Supported data models:
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Profile
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#Credential
// 	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#CachedDIDDocument
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#meta-data
//	- https://w3c-ccg.github.io/universal-wallet-interop-spec/#connection
//
func (c *Wallet) Get(contentType ContentType, contentID string) (json.RawMessage, error) {
	return c.contents.Get(contentType, contentID)
}

// Query returns a collection of results based on current wallet contents.
//
// Supported Query Types:
// 	- https://www.w3.org/TR/json-ld11-framing
// 	- https://identity.foundation/presentation-exchange
//
func (c *Wallet) Query(query *QueryParams) ([]json.RawMessage, error) {
	// TODO to be added #2433
	return nil, fmt.Errorf("to be implemented")
}

// Issue adds proof to a Verifiable Credential.
//
//	Args:
//		- A verifiable credential with or without proof
//		- Proof options
//
func (c *Wallet) Issue(authToken string, credential json.RawMessage,
	options *ProofOptions) (*verifiable.Credential, error) {
	vc, err := verifiable.ParseCredential(credential, verifiable.WithDisabledProofCheck())
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	purpose := did.AssertionMethod

	err = c.validateProofOption(options, purpose)
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
//		- List of verifiable credentials IDs.
//		- Proof options
//
func (c *Wallet) Prove(credentialIDs []string, options *ProofOptions) (json.RawMessage, error) {
	// TODO to be added #2433
	return nil, fmt.Errorf("to be implemented")
}

// Verify takes Takes a Verifiable Credential or Verifiable Presentation as input,.
//
//	Args:
//		- a Verifiable Credential or Verifiable Presentation
//
// Returns: a boolean verified, and an error if verified is false.
func (c *Wallet) Verify(raw json.RawMessage) (bool, error) {
	// TODO to be added #2433
	return false, fmt.Errorf("to be implemented")
}

func (c *Wallet) addLinkedDataProof(authToken string, p provable, opts *ProofOptions,
	relationship did.VerificationRelationship) error {
	s, err := newKMSSigner(authToken, c.ctx.Crypto(), opts)
	if err != nil {
		return err
	}

	var signatureSuite signer.SignatureSuite

	var processorOpts []jsonld.ProcessorOpts

	switch opts.ProofType {
	case Ed25519Signature2018:
		signatureSuite = ed25519signature2018.New(suite.WithSigner(s))
	case JSONWebSignature2020:
		signatureSuite = jsonwebsignature2020.New(suite.WithSigner(s))
	case BbsBlsSignature2020:
		// TODO document loader to be part of common API, to be removed
		bbsLoader, e := bbsJSONLDDocumentLoader()
		if e != nil {
			return e
		}

		processorOpts = append(processorOpts, jsonld.WithDocumentLoader(bbsLoader))

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

	err = p.AddLinkedDataProof(signingCtx, processorOpts...)
	if err != nil {
		return fmt.Errorf("failed to add linked data proof: %w", err)
	}

	return nil
}

func (c *Wallet) validateProofOption(opts *ProofOptions, method did.VerificationRelationship) error {
	if opts == nil || opts.Controller == "" {
		return errors.New("invalid proof option, 'controller' is required")
	}

	didDoc, err := c.getDIDDocument(opts.Controller)
	if err != nil {
		return err
	}

	err = c.validateVerificationMethod(didDoc, opts, method)
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

// TODO stored DIDResolution response & DID Doc metadata should be read first before trying to resolve using VDR.
func (c *Wallet) getDIDDocument(didID string) (*did.Doc, error) {
	doc, err := c.ctx.VDRegistry().Resolve(didID)
	//  if DID not found in VDR, look through in wallet content storage.
	if err != nil {
		docBytes, err := c.contents.Get(DIDResolutionResponse, didID)
		if err != nil {
			return nil, fmt.Errorf("failed to read DID document from wallet store or from VDR: %w", err)
		}

		doc, err = did.ParseDocumentResolution(docBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse stored DID: %w", err)
		}

		return doc.DIDDocument, nil
	}

	return doc.DIDDocument, nil
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
func addContext(v interface{}, context string) {
	if vc, ok := v.(*verifiable.Credential); ok {
		for _, ctx := range vc.Context {
			if ctx == context {
				return
			}
		}

		vc.Context = append(vc.Context, context)
	}
}

// TODO: context should not be loaded here, the loader should be defined once for the whole system.
func bbsJSONLDDocumentLoader() (*jld.CachingDocumentLoader, error) {
	loader := presexch.CachingJSONLDLoader()

	reader, err := ld.DocumentFromReader(strings.NewReader(contextBBSContent))
	if err != nil {
		return nil, err
	}

	loader.AddDocument(bbsContext, reader)

	return loader, nil
}

const contextBBSContent = `{
  "@context": {
    "@version": 1.1,
    "id": "@id",
    "type": "@type",
    "BbsBlsSignature2020": {
      "@id": "https://w3id.org/security#BbsBlsSignature2020",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "challenge": "https://w3id.org/security#challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "domain": "https://w3id.org/security#domain",
        "proofValue": "https://w3id.org/security#proofValue",
        "nonce": "https://w3id.org/security#nonce",
        "proofPurpose": {
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "assertionMethod": {
              "@id": "https://w3id.org/security#assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "https://w3id.org/security#authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      }
    },
    "BbsBlsSignatureProof2020": {
      "@id": "https://w3id.org/security#BbsBlsSignatureProof2020",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",

        "challenge": "https://w3id.org/security#challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "domain": "https://w3id.org/security#domain",
        "nonce": "https://w3id.org/security#nonce",
        "proofPurpose": {
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "sec": "https://w3id.org/security#",
            "assertionMethod": {
              "@id": "https://w3id.org/security#assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "https://w3id.org/security#authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "proofValue": "https://w3id.org/security#proofValue",
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      }
    },
    "Bls12381G2Key2020": "https://w3id.org/security#Bls12381G2Key2020"
  }
}`
