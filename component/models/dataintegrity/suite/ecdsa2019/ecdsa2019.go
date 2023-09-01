/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdsa2019

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"

	"github.com/multiformats/go-multibase"
	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/models"
	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity/suite"
	"github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	signatureverifier "github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
)

const (
	// SuiteType "ecdsa-2019" is the data integrity Type identifier for the suite
	// implementing ecdsa signatures with RDF canonicalization as per this
	// spec:https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-2019
	SuiteType = "ecdsa-2019"
)

// SignerGetter returns a Signer, which must sign with the private key matching
// the public key provided in models.ProofOptions.VerificationMethod.
type SignerGetter func(pub *jwk.JWK) (Signer, error)

// WithStaticSigner sets the Suite to use a fixed Signer, with externally-chosen signing key.
//
// Use when a signing Suite is initialized for a single signature, then thrown away.
func WithStaticSigner(signer Signer) SignerGetter {
	return func(*jwk.JWK) (Signer, error) {
		return signer, nil
	}
}

// WithLocalKMSSigner returns a SignerGetter that will sign using the given localkms, using the private key matching
// the given public key.
func WithLocalKMSSigner(kms models.KeyManager, kmsSigner KMSSigner) SignerGetter {
	return func(pub *jwk.JWK) (Signer, error) {
		kid, err := kmsKID(pub)
		if err != nil {
			return nil, err
		}

		kh, err := kms.Get(kid)
		if err != nil {
			return nil, err
		}

		return &wrapSigner{
			kmsSigner: kmsSigner,
			kh:        kh,
		}, nil
	}
}

// A KMSSigner is able to sign messages.
type KMSSigner interface {
	// Sign will sign msg using a matching signature primitive in kh key handle of a private key
	// returns:
	// 		signature in []byte
	//		error in case of errors
	Sign(msg []byte, kh interface{}) ([]byte, error)
}

// A Signer is able to sign messages.
type Signer interface {
	// Sign will sign msg using a private key internal to the Signer.
	// returns:
	// 		signature in []byte
	//		error in case of errors
	Sign(msg []byte) ([]byte, error)
}

// A Verifier is able to verify messages.
type Verifier interface {
	// Verify will verify a signature for the given msg using a matching signature primitive in kh key handle of
	// a public key
	// returns:
	// 		error in case of errors or nil if signature verification was successful
	Verify(pubKey *signatureverifier.PublicKey, msg, signature []byte) error
}

// Suite implements the ecdsa-2019 data integrity cryptographic suite.
type Suite struct {
	ldLoader     ld.DocumentLoader
	p256Verifier Verifier
	p384Verifier Verifier
	signerGetter SignerGetter
}

// Options provides initialization options for Suite.
type Options struct {
	LDDocumentLoader ld.DocumentLoader
	P256Verifier     Verifier
	P384Verifier     Verifier
	SignerGetter     SignerGetter
}

// SuiteInitializer is the initializer for Suite.
type SuiteInitializer func() (suite.Suite, error)

// New constructs an initializer for Suite.
func New(options *Options) SuiteInitializer {
	return func() (suite.Suite, error) {
		return &Suite{
			ldLoader:     options.LDDocumentLoader,
			p256Verifier: options.P256Verifier,
			p384Verifier: options.P384Verifier,
			signerGetter: options.SignerGetter,
		}, nil
	}
}

type initializer SuiteInitializer

// Signer private, implements suite.SignerInitializer.
func (i initializer) Signer() (suite.Signer, error) {
	return i()
}

// Verifier private, implements suite.VerifierInitializer.
func (i initializer) Verifier() (suite.Verifier, error) {
	return i()
}

// Type private, implements suite.SignerInitializer and
// suite.VerifierInitializer.
func (i initializer) Type() string {
	return SuiteType
}

// SignerInitializerOptions provides options for a SignerInitializer.
type SignerInitializerOptions struct {
	LDDocumentLoader ld.DocumentLoader
	SignerGetter     SignerGetter
}

// NewSignerInitializer returns a suite.SignerInitializer that initializes an ecdsa-2019
// signing Suite with the given SignerInitializerOptions.
func NewSignerInitializer(options *SignerInitializerOptions) suite.SignerInitializer {
	return initializer(New(&Options{
		LDDocumentLoader: options.LDDocumentLoader,
		SignerGetter:     options.SignerGetter,
	}))
}

// VerifierInitializerOptions provides options for a VerifierInitializer.
type VerifierInitializerOptions struct {
	LDDocumentLoader ld.DocumentLoader // required
	P256Verifier     Verifier          // optional
	P384Verifier     Verifier          // optional
}

// NewVerifierInitializer returns a suite.VerifierInitializer that initializes an
// ecdsa-2019 verification Suite with the given VerifierInitializerOptions.
func NewVerifierInitializer(options *VerifierInitializerOptions) suite.VerifierInitializer {
	p256Verifier, p384Verifier := options.P256Verifier, options.P384Verifier

	if p256Verifier == nil {
		p256Verifier = signatureverifier.NewECDSAES256SignatureVerifier()
	}

	if p384Verifier == nil {
		p384Verifier = signatureverifier.NewECDSAES384SignatureVerifier()
	}

	return initializer(New(&Options{
		LDDocumentLoader: options.LDDocumentLoader,
		P256Verifier:     p256Verifier,
		P384Verifier:     p384Verifier,
	}))
}

const (
	ldCtxKey = "@context"
)

// CreateProof implements the ecdsa-2019 cryptographic suite for Add Proof:
// https://www.w3.org/TR/vc-di-ecdsa/#add-proof-ecdsa-2019
func (s *Suite) CreateProof(doc []byte, opts *models.ProofOptions) (*models.Proof, error) {
	docHash, vmKey, _, err := s.transformAndHash(doc, opts)
	if err != nil {
		return nil, err
	}

	sig, err := sign(docHash, vmKey, s.signerGetter)
	if err != nil {
		return nil, err
	}

	sigStr, err := multibase.Encode(multibase.Base58BTC, sig)
	if err != nil {
		return nil, err
	}

	p := &models.Proof{
		Type:               models.DataIntegrityProof,
		CryptoSuite:        SuiteType,
		ProofPurpose:       opts.Purpose,
		Domain:             opts.Domain,
		Challenge:          opts.Challenge,
		VerificationMethod: opts.VerificationMethod.ID,
		ProofValue:         sigStr,
		Created:            opts.Created.Format(models.DateTimeFormat),
	}

	return p, nil
}

func (s *Suite) transformAndHash(doc []byte, opts *models.ProofOptions) ([]byte, *jwk.JWK, Verifier, error) {
	docData := make(map[string]interface{})

	err := json.Unmarshal(doc, &docData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ecdsa-2019 suite expects JSON-LD payload: %w", err)
	}

	vmKey := opts.VerificationMethod.JSONWebKey()
	if vmKey == nil {
		return nil, nil, nil, errors.New("verification method needs JWK")
	}

	var (
		h        hash.Hash
		verifier Verifier
	)

	switch vmKey.Crv {
	case "P-256":
		h = sha256.New()
		verifier = s.p256Verifier
	case "P-384":
		h = sha512.New384()
		verifier = s.p384Verifier
	default:
		return nil, nil, nil, errors.New("unsupported ECDSA curve")
	}

	confData := proofConfig(docData[ldCtxKey], opts)

	if opts.ProofType != "DataIntegrityProof" || opts.SuiteType != SuiteType {
		return nil, nil, nil, suite.ErrProofTransformation
	}

	canonDoc, err := canonicalize(docData, s.ldLoader)
	if err != nil {
		return nil, nil, nil, err
	}

	canonConf, err := canonicalize(confData, s.ldLoader)
	if err != nil {
		return nil, nil, nil, err
	}

	docHash := hashData(canonDoc, canonConf, h)

	return docHash, vmKey, verifier, nil
}

// VerifyProof implements the ecdsa-2019 cryptographic suite for Verify Proof:
// https://www.w3.org/TR/vc-di-ecdsa/#verify-proof-ecdsa-2019
func (s *Suite) VerifyProof(doc []byte, proof *models.Proof, opts *models.ProofOptions) error {
	message, vmKey, verifier, err := s.transformAndHash(doc, opts)
	if err != nil {
		return err
	}

	_, signature, err := multibase.Decode(proof.ProofValue)
	if err != nil {
		return fmt.Errorf("decoding proofValue: %w", err)
	}

	err = verifier.Verify(&signatureverifier.PublicKey{JWK: vmKey}, message, signature)
	if err != nil {
		return fmt.Errorf("failed to verify ecdsa-2019 DI proof: %w", err)
	}

	return nil
}

// RequiresCreated returns false, as the ecdsa-2019 cryptographic suite does not
// require the use of the models.Proof.Created field.
func (s *Suite) RequiresCreated() bool {
	return false
}

func canonicalize(data map[string]interface{}, loader ld.DocumentLoader) ([]byte, error) {
	out, err := processor.Default().GetCanonicalDocument(data, processor.WithDocumentLoader(loader))
	if err != nil {
		return nil, fmt.Errorf("canonicalizing signature base data: %w", err)
	}

	return out, nil
}

func hashData(transformedDoc, confData []byte, h hash.Hash) []byte {
	h.Write(transformedDoc)
	docHash := h.Sum(nil)

	h.Reset()
	h.Write(confData)
	result := h.Sum(docHash)

	return result
}

func proofConfig(docCtx interface{}, opts *models.ProofOptions) map[string]interface{} {
	return map[string]interface{}{
		ldCtxKey:             docCtx,
		"type":               models.DataIntegrityProof,
		"cryptosuite":        SuiteType,
		"verificationMethod": opts.VerificationMethodID,
		"created":            opts.Created.Format(models.DateTimeFormat),
		"proofPurpose":       opts.Purpose,
	}
}

// TODO copied from kid_creator.go, should move there: https://github.com/hyperledger/aries-framework-go/issues/3614
func kmsKID(key *jwk.JWK) (string, error) {
	tp, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("computing thumbprint for kms kid: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(tp), nil
}

type wrapSigner struct {
	kmsSigner KMSSigner
	kh        interface{}
}

// Sign signs using wrapped kms and key handle.
func (s *wrapSigner) Sign(msg []byte) ([]byte, error) {
	return s.kmsSigner.Sign(msg, s.kh)
}

func sign(sigBase []byte, key *jwk.JWK, signerGetter SignerGetter) ([]byte, error) {
	signer, err := signerGetter(key)
	if err != nil {
		return nil, err
	}

	sig, err := signer.Sign(sigBase)
	if err != nil {
		return nil, err
	}

	return sig, nil
}
