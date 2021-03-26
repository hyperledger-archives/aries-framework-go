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
//		- auth token for unlocking kms.
//		- A verifiable credential with or without proof.
//		- Proof options.
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
// 		- auth token for unlocking kms.
//		- list of interfaces (string of credential IDs which can be resolvable to stored credentials in wallet or
//		raw credential).
//		- proof options
//
func (c *Wallet) Prove(authToken string, proofOptions *ProofOptions, credentials ...CredentialToPresent) (*verifiable.Presentation, error) { //nolint: lll
	resolved, err := c.resolveCredentials(credentials...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve credentials from request: %w", err)
	}

	purpose := did.Authentication

	err = c.validateProofOption(proofOptions, purpose)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare proof: %w", err)
	}

	presentation, err := verifiable.NewPresentation(verifiable.WithCredentials(resolved...))
	if err != nil {
		return nil, fmt.Errorf("failed to prepare presentation: %w", err)
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
func (c *Wallet) Verify(options VerificationOption) (bool, error) {
	requestOpts := &verifyOpts{}

	options(requestOpts)

	switch {
	case requestOpts.credentialID != "":
		raw, err := c.contents.Get(Credential, requestOpts.credentialID)
		if err != nil {
			return false, fmt.Errorf("failed to get credential: %w", err)
		}

		return c.verifyCredential(raw)
	case len(requestOpts.rawCredential) > 0:
		return c.verifyCredential(requestOpts.rawCredential)
	case len(requestOpts.rawPresentation) > 0:
		return c.verifyPresentation(requestOpts.rawPresentation)
	default:
		return false, fmt.Errorf("invalid verify request")
	}
}

func (c *Wallet) resolveCredentials(credentials ...CredentialToPresent) ([]*verifiable.Credential, error) {
	var response []*verifiable.Credential

	opts := &proveOpts{}

	for _, opt := range credentials {
		opt(opts)
	}

	for _, id := range opts.storedCredentials {
		raw, err := c.contents.Get(Credential, id)
		if err != nil {
			return nil, err
		}

		// proof check is disabled while resolving credentials from store. A wallet UI may or may not choose to
		// show credentials as verified. If a wallet implementation chooses to show credentials as 'verified' it
		// may to call 'wallet.Verify()' for each credential being presented.
		// (More details can be found in issue #2677).
		credential, err := verifiable.ParseCredential(raw, verifiable.WithDisabledProofCheck())
		if err != nil {
			return nil, err
		}

		response = append(response, credential)
	}

	for _, raw := range opts.rawCredentials {
		// proof check is disabled while resolving credentials from raw bytes. A wallet UI may or may not choose to
		// show credentials as verified. If a wallet implementation chooses to show credentials as 'verified' it
		// may to call 'wallet.Verify()' for each credential being presented.
		// (More details can be found in issue #2677).
		credential, err := verifiable.ParseCredential(raw, verifiable.WithDisabledProofCheck())
		if err != nil {
			return nil, err
		}

		response = append(response, credential)
	}

	if len(opts.credentials) > 0 {
		response = append(response, opts.credentials...)
	}

	return response, nil
}

func (c *Wallet) verifyCredential(credential json.RawMessage) (bool, error) {
	// TODO resolve stored DID documents in wallet
	opts := verifiable.WithPublicKeyFetcher(
		verifiable.NewDIDKeyResolver(c.ctx.VDRegistry()).PublicKeyFetcher(),
	)

	_, err := verifiable.ParseCredential(credential, opts)
	if err != nil {
		return false, fmt.Errorf("credential verification failed: %w", err)
	}

	return true, nil
}

func (c *Wallet) verifyPresentation(presentation json.RawMessage) (bool, error) {
	// TODO resolve stored DID documents in wallet
	publicKeyFetcher := verifiable.NewDIDKeyResolver(c.ctx.VDRegistry()).PublicKeyFetcher()

	vp, err := verifiable.ParsePresentation(presentation, verifiable.WithPresPublicKeyFetcher(publicKeyFetcher))
	if err != nil {
		return false, fmt.Errorf("presentation verification failed: %w", err)
	}

	// verify proof of each credential
	for _, cred := range vp.Credentials() {
		vc, err := json.Marshal(cred)
		if err != nil {
			return false, fmt.Errorf("failed to read credentials from presentation: %w", err)
		}

		_, err = c.verifyCredential(vc)
		if err != nil {
			return false, fmt.Errorf("presentation verification failed: %w", err)
		}
	}

	return true, nil
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
